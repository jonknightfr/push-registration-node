/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
 */
/**
 * jon.knight@forgerock.com
 *
 * A node that registers a mobile device for SNS push notifications
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.services.push.*;
import org.forgerock.openam.services.push.dispatch.handlers.ClusterMessageHandler;
import org.forgerock.openam.session.SessionCookies;
import org.forgerock.util.encode.Base64;

import javax.inject.Inject;
import java.util.*;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.services.push.PushNotificationConstants.JWT;
import static org.forgerock.openam.services.push.PushNotificationConstants.*;
import javax.security.auth.callback.Callback;

import org.forgerock.json.resource.NotFoundException;
import org.forgerock.openam.authentication.callbacks.helpers.QRCallbackBuilder;
import org.forgerock.openam.core.rest.devices.DevicePersistenceException;
import org.forgerock.openam.core.rest.devices.push.PushDeviceSettings;
import org.forgerock.openam.core.rest.devices.push.UserPushDeviceProfileManager;
import org.forgerock.am.cts.exceptions.CoreTokenException;
import org.forgerock.openam.services.push.dispatch.predicates.Predicate;
import org.forgerock.openam.services.push.dispatch.predicates.PushMessageChallengeResponsePredicate;
import org.forgerock.openam.services.push.dispatch.predicates.SignedJwtVerificationPredicate;
import org.forgerock.util.encode.Base64url;

import org.forgerock.openam.services.push.DefaultMessageTypes;
import org.forgerock.openam.services.push.MessageId;
import org.forgerock.openam.services.push.MessageIdFactory;
import org.forgerock.openam.services.push.PushNotificationException;
import org.forgerock.openam.services.push.PushNotificationService;
import com.google.common.collect.ImmutableList;
import org.forgerock.util.i18n.PreferredLocales;


/**
 * An authentication node integrating with iProov face recognition solution.
 */

@Node.Metadata(outcomeProvider = PushRegNode.OutcomeProvider.class,
        configClass = PushRegNode.Config.class)
public class PushRegNode implements Node {

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String issuer() { return "ForgeRock"; }
        @Attribute(order = 200)
        default int timeout() { return 4000; }
        @Attribute(order = 300)
        default int retries() { return 15; }
        @Attribute(order = 400)
        default String color() { return "519387"; }
        @Attribute(order = 500)
        default String imgUrl() { return ""; }
    }


    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "PushRegNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);


    private final UserPushDeviceProfileManager userPushDeviceProfileManager;
    private final PushNotificationService pushNotificationService;
    private final MessageIdFactory messageIdFactory;
    private final SessionCookies sessionCookies;
    private BaseURLProviderFactory baseUrlProviderFactory;

    /** The key for the Message Id query component of the QR code. */
    static final String MESSAGE_ID_QR_CODE_KEY = "m";
    /** The key for the shared secret query component of the QR code. */
    static final String SHARED_SECRET_QR_CODE_KEY = "s";
    /** The key for the bgcolour query component of the QR code. */
    static final String BGCOLOUR_QR_CODE_KEY = "b";
    /** The key for the Issuer query component of the QR code. */
    static final String REG_QR_CODE_KEY = "r";
    /** The key for the Issuer query component of the QR code. */
    static final String AUTH_QR_CODE_KEY = "a";
    /** The key for the Issuer query component of the QR code. */
    static final String IMG_QR_CODE_KEY = "image";
    /** The key for the loadbalancer information component of the QR code. */
    static final String LOADBALANCER_DATA_QR_CODE_KEY = "l";
    /** The key for the challenge inside the registration challenge. */
    static final String CHALLENGE_QR_CODE_KEY = "c";
    /** The key for the total JWS challenge for registration. */
    static final String ISSUER_QR_CODE_KEY = "issuer";

    static final String PUSH_UUID = "PUSH_UUID";
    static final String PUSH_SHAREDSECRET = "PUSH_SHAREDSECRET";
    static final String PUSH_CHALLENGE = "PUSH_CHALLENGE";
    static final String PUSH_RETRIES = "PUSH_RETRIES";
    static final String PUSH_MESSAGEID = "PUSH_MESSAGEID";


    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public PushRegNode(@Assisted Config config, CoreWrapper coreWrapper,
                       UserPushDeviceProfileManager userPushDeviceProfileManager, PushNotificationService pushNotificationService,
                       SessionCookies sessionCookies,
                       MessageIdFactory messageIdFactory) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
        this.userPushDeviceProfileManager = userPushDeviceProfileManager;
        this.pushNotificationService = pushNotificationService;
        this.sessionCookies = sessionCookies;
        this.messageIdFactory = messageIdFactory;
    }


    private Callback createQRCodeCallback(PushDeviceSettings deviceProfile, AMIdentity id, String messageId, String challenge, String serverUrl, String realm) throws NodeProcessException {

        QRCallbackBuilder builder;
        try {
            builder = new QRCallbackBuilder().withUriScheme("pushauth")
                    .withUriHost("push")
                    .withUriPath("forgerock")
                    .withUriPort(id.getName())
                    .withCallbackIndex(0)
                    .addUriQueryComponent(LOADBALANCER_DATA_QR_CODE_KEY,
                            Base64url.encode(sessionCookies.getLBCookie().getBytes()))
                    .addUriQueryComponent(ISSUER_QR_CODE_KEY, Base64url.encode(config.issuer().getBytes()))
                    .addUriQueryComponent(MESSAGE_ID_QR_CODE_KEY, messageId)
                    .addUriQueryComponent(SHARED_SECRET_QR_CODE_KEY,
                            Base64url.encode(org.forgerock.util.encode.Base64.decode(deviceProfile.getSharedSecret())))
                    .addUriQueryComponent(BGCOLOUR_QR_CODE_KEY, config.color())
                    .addUriQueryComponent(CHALLENGE_QR_CODE_KEY, Base64url.encode(org.forgerock.util.encode.Base64.decode(challenge)))
                    .addUriQueryComponent(REG_QR_CODE_KEY, Base64url.encode((serverUrl + "/json" + pushNotificationService.getServiceAddressFor(realm, DefaultMessageTypes.REGISTER)).getBytes()))
                    .addUriQueryComponent(AUTH_QR_CODE_KEY, Base64url.encode((serverUrl + "/json" + pushNotificationService.getServiceAddressFor(realm, DefaultMessageTypes.AUTHENTICATE)).getBytes()));
        } catch (PushNotificationException e) {
            debug.error("Unable to generate QR code");
            throw new NodeProcessException("Unable to generate QR code");
        }

        if (config.imgUrl() != null) {
            builder.addUriQueryComponent(IMG_QR_CODE_KEY, Base64url.encode(config.imgUrl().getBytes()));
        }

        return builder.build();
    }


    private void saveDeviceDetailsUnderUserAccount(JsonValue deviceResponse, String username, String realm, String deviceId, String sharedSecret) {
        PushDeviceSettings newDeviceRegistrationProfile = new PushDeviceSettings();
        newDeviceRegistrationProfile.setDeviceName("Push Device");

        try {
            newDeviceRegistrationProfile.setUUID(deviceId);
            newDeviceRegistrationProfile.setSharedSecret(sharedSecret);
            newDeviceRegistrationProfile.setCommunicationId(deviceResponse.get(COMMUNICATION_ID).asString());
            newDeviceRegistrationProfile.setDeviceMechanismUID(deviceResponse.get(MECHANISM_UID).asString());
            newDeviceRegistrationProfile.setCommunicationType(deviceResponse.get(COMMUNICATION_TYPE).asString());
            newDeviceRegistrationProfile.setDeviceType(deviceResponse.get(DEVICE_TYPE).asString());
            newDeviceRegistrationProfile.setDeviceId(deviceResponse.get(DEVICE_ID).asString());
            newDeviceRegistrationProfile.setIssuer(config.issuer());
        } catch (NullPointerException npe) {
            debug.error("Blank value for necessary data from device response, {}", deviceResponse);
        }

        /* RECOVERY CODES NOT IMPLEMENTED
        try {
            recoveryCodes = recoveryCodeGenerator.generateCodes(10, Alphabet.ALPHANUMERIC, false);
            newDeviceRegistrationProfile.setRecoveryCodes(recoveryCodes);
        } catch (CodeException e) {
            debug.error("Insufficient recovery code generation occurred.");
        }
        */

        try {
            userPushDeviceProfileManager.saveDeviceProfile(username, realm, newDeviceRegistrationProfile);
        } catch (DevicePersistenceException e) {
            debug.error("Unable to store device profile.");
        }
    }



    private Callback[] generateCallbacks(TreeContext context, PushDeviceSettings newDeviceRegistrationProfile, String messageId, String challenge) {
        String realm = context.sharedState.get(SharedStateConstants.REALM).asString();
        String username = context.sharedState.get(USERNAME).asString();
        AMIdentity userIdentity = coreWrapper.getIdentity(username, realm);

        Callback QRcallback;
        try {
            QRcallback = createQRCodeCallback(newDeviceRegistrationProfile, userIdentity, messageId, challenge, context.request.serverUrl, realm);
        } catch (NodeProcessException e) {
            return null;
        }

        PollingWaitCallback pollingWaitCallback = PollingWaitCallback.makeCallback()
                .withWaitTime(String.valueOf(config.timeout()))
                .build();

        Callback[] callbacks = new Callback[]{QRcallback, pollingWaitCallback};

        return callbacks;
    }


    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        debug.error("PushRegNode started.");
        String realm = context.sharedState.get(SharedStateConstants.REALM).asString();
        String username = context.sharedState.get(USERNAME).asString();


        Optional<PollingWaitCallback> pollingCallback = context.getCallback(PollingWaitCallback.class);
        if (pollingCallback.isPresent()) {
            if (!context.sharedState.isDefined(PUSH_MESSAGEID)) {
                debug.error("Unable to find push message ID in sharedState");
                throw new NodeProcessException("Unable to find push message ID");
            }

            String pushMessageId = context.sharedState.get(PUSH_MESSAGEID).asString();
            try {
                MessageId messageId = messageIdFactory.create(pushMessageId, realm);
                ClusterMessageHandler messageHandler = pushNotificationService.getMessageHandlers(realm).get(messageId.getMessageType());
                if (messageHandler == null) {
                    debug.error("The push message corresponds to {} message type which is not registered in the {} realm",
                            messageId.getMessageType(), realm);
                    throw new NodeProcessException("Unknown message type");
                }
                MessageState state = messageHandler.check(messageId);

                JsonValue newSharedState = context.sharedState.copy();
                if (state == null) {
                    debug.error("The push message with ID {} has timed out", messageId.toString());
                    throw new NodeProcessException("Message timed out");
                }

                switch (state) {
                    case SUCCESS:
                        JsonValue pushContent = messageHandler.getContents(messageId);
                        messageHandler.delete(messageId);
                        if (pushContent != null) {
                            saveDeviceDetailsUnderUserAccount(pushContent, username, realm, context.sharedState.get(PUSH_UUID).asString(), context.sharedState.get(PUSH_SHAREDSECRET).asString());
                            newSharedState.remove(PUSH_MESSAGEID);
                            newSharedState.remove(PUSH_SHAREDSECRET);
                            newSharedState.remove(PUSH_UUID);
                            newSharedState.remove(PUSH_CHALLENGE);
                            return goTo("success").replaceSharedState(newSharedState).build();
                        } else throw new NodeProcessException("Failed to save device to user profile");
                    case DENIED:
                        messageHandler.delete(messageId);
                        throw new NodeProcessException("App denied registration");
                    case UNKNOWN:
                        int attempts = context.sharedState.get(PUSH_RETRIES).asInteger();
                        if (attempts >= config.retries()) {
                            return goTo("timeout").build();
                        } else {

                            PushDeviceSettings newDeviceRegistrationProfile = userPushDeviceProfileManager.createDeviceProfile();
                            newDeviceRegistrationProfile.setUUID(newSharedState.get(PUSH_UUID).asString());
                            newDeviceRegistrationProfile.setSharedSecret(newSharedState.get(PUSH_SHAREDSECRET).asString());
                            String challenge = newSharedState.get(PUSH_CHALLENGE).asString();
                            String messageIdStr = newSharedState.get(PUSH_MESSAGEID).asString();
                            newSharedState.put(PUSH_RETRIES, attempts+1);

                            Callback[] callbacks = generateCallbacks(context, newDeviceRegistrationProfile, messageIdStr, challenge);

                            return send(callbacks)
                                    .replaceSharedState(newSharedState.put(PUSH_MESSAGEID, messageIdStr))
                                    .build();
                        }
                    default:
                        throw new NodeProcessException("Unrecognized push message status: " + state);
                }
            } catch (PushNotificationException | CoreTokenException ex) {
                throw new NodeProcessException("An unexpected error occurred while verifying the push result", ex);
            }

        } else {
            JsonValue newSharedState = context.sharedState.copy();

            PushDeviceSettings newDeviceRegistrationProfile = userPushDeviceProfileManager.createDeviceProfile();
            debug.error(newDeviceRegistrationProfile.toString());

            MessageId messageId = messageIdFactory.create(DefaultMessageTypes.REGISTER);

            //Callback[] callbacks = generateCallbacks(context, username, realm, newDeviceRegistrationProfile, messageId);

            String challenge = userPushDeviceProfileManager.createRandomBytes();

            Callback[] callbacks = generateCallbacks(context, newDeviceRegistrationProfile, messageId.toString(), challenge);
            newSharedState.put(PUSH_UUID, newDeviceRegistrationProfile.getUUID());
            newSharedState.put(PUSH_SHAREDSECRET, newDeviceRegistrationProfile.getSharedSecret());
            newSharedState.put(PUSH_CHALLENGE, challenge);
            newSharedState.put(PUSH_MESSAGEID, messageId.toString());
            newSharedState.put(PUSH_RETRIES, 0);


            byte[] secret = Base64.decode(newDeviceRegistrationProfile.getSharedSecret());

            Set<Predicate> servicePredicates = new HashSet<>();

            servicePredicates.add(new SignedJwtVerificationPredicate(secret, JWT));
            servicePredicates.add(new PushMessageChallengeResponsePredicate(secret, challenge, JWT));

            try {
                PushNotificationService pushService = getPushNotificationService(realm);

                Set<Predicate> predicates = pushService.getMessagePredicatesFor(realm).get(DefaultMessageTypes.REGISTER);
                if (predicates != null) {
                    servicePredicates.addAll(predicates);
                }

                pushService.getMessageDispatcher(realm).expectInCluster(messageId, servicePredicates);
            } catch (NotFoundException | PushNotificationException e) {
                debug.error("Unable to read service addresses for Push Notification Service.");
            } catch (CoreTokenException e) {
                debug.error("Unable to persist token in core token service.", e);
            } catch (NodeProcessException e) {
                debug.error("Unable to get push notification service");
            }

            return send(callbacks)
                    .replaceSharedState(newSharedState.put(PUSH_MESSAGEID, messageId.toString()))
                    .build();
        }
    }


    private PushNotificationService getPushNotificationService(String realm) throws NodeProcessException {
        try {
            pushNotificationService.init(realm);
            return pushNotificationService;
        } catch (PushNotificationException e) {
            throw new NodeProcessException(e);
        }
    }


    private Action.ActionBuilder goTo(String outcome) {
        return Action.goTo(outcome);
    }


    static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        private static final String BUNDLE = PushRegNode.class.getName().replace(".", "/");

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome("success", bundle.getString("success")),
                    new Outcome("timeout", bundle.getString("timeout")));
        }
    }
}
