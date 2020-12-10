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
/*
  jon.knight@forgerock.com
  <p>
  A node that registers a mobile device for SNS push notifications
 */


package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.services.push.PushNotificationConstants.COMMUNICATION_ID;
import static org.forgerock.openam.services.push.PushNotificationConstants.COMMUNICATION_TYPE;
import static org.forgerock.openam.services.push.PushNotificationConstants.DEVICE_ID;
import static org.forgerock.openam.services.push.PushNotificationConstants.DEVICE_TYPE;
import static org.forgerock.openam.services.push.PushNotificationConstants.JWT;
import static org.forgerock.openam.services.push.PushNotificationConstants.MECHANISM_UID;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.forgerock.am.cts.exceptions.CoreTokenException;
import org.forgerock.guice.core.InjectorHolder;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.NotFoundException;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.authentication.callbacks.helpers.QRCallbackBuilder;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.rest.devices.DevicePersistenceException;
import org.forgerock.openam.core.rest.devices.push.PushDeviceSettings;
import org.forgerock.openam.core.rest.devices.push.UserPushDeviceProfileManager;
import org.forgerock.openam.services.push.DefaultMessageTypes;
import org.forgerock.openam.services.push.MessageId;
import org.forgerock.openam.services.push.MessageIdFactory;
import org.forgerock.openam.services.push.MessageState;
import org.forgerock.openam.services.push.PushNotificationException;
import org.forgerock.openam.services.push.PushNotificationService;
import org.forgerock.openam.services.push.dispatch.handlers.ClusterMessageHandler;
import org.forgerock.openam.services.push.dispatch.predicates.Predicate;
import org.forgerock.openam.services.push.dispatch.predicates.PushMessageChallengeResponsePredicate;
import org.forgerock.openam.services.push.dispatch.predicates.SignedJwtVerificationPredicate;
import org.forgerock.openam.session.SessionCookies;
import org.forgerock.openam.utils.Alphabet;
import org.forgerock.openam.utils.CodeException;
import org.forgerock.openam.utils.RecoveryCodeGenerator;
import org.forgerock.util.encode.Base64;
import org.forgerock.util.encode.Base64url;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.idm.AMIdentity;


@Node.Metadata(outcomeProvider = PushRegNode.OutcomeProvider.class,
        configClass = PushRegNode.Config.class, tags = {"mfa", "multi-factor authentication"})
public class PushRegNode implements Node {

    /**
     * The key for the Message Id query component of the QR code.
     */
    static final String MESSAGE_ID_QR_CODE_KEY = "m";
    /**
     * The key for the shared secret query component of the QR code.
     */
    static final String SHARED_SECRET_QR_CODE_KEY = "s";
    /**
     * The key for the bgcolour query component of the QR code.
     */
    static final String BGCOLOUR_QR_CODE_KEY = "b";
    /**
     * The key for the Issuer query component of the QR code.
     */
    static final String REG_QR_CODE_KEY = "r";
    /**
     * The key for the Issuer query component of the QR code.
     */
    static final String AUTH_QR_CODE_KEY = "a";
    /**
     * The key for the Issuer query component of the QR code.
     */
    static final String IMG_QR_CODE_KEY = "image";
    /**
     * The key for the loadbalancer information component of the QR code.
     */
    static final String LOADBALANCER_DATA_QR_CODE_KEY = "l";
    /**
     * The key for the challenge inside the registration challenge.
     */
    static final String CHALLENGE_QR_CODE_KEY = "c";
    /**
     * Number of recovery codes to generate for webauthn devices by default.
     */
    static final int NUM_RECOVERY_CODES = 10;
    static final String ISSUER_QR_CODE_KEY = "issuer";
    static final String PUSH_UUID = "PUSH_UUID";
    static final String PUSH_SHAREDSECRET = "PUSH_SHAREDSECRET";
    static final String PUSH_CHALLENGE = "PUSH_CHALLENGE";
    static final String PUSH_RETRIES = "PUSH_RETRIES";
    static final String PUSH_MESSAGEID = "PUSH_MESSAGEID";
    private final Config config;
    private final CoreWrapper coreWrapper;
    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final UserPushDeviceProfileManager userPushDeviceProfileManager;
    private final PushNotificationService pushNotificationService;
    private final MessageIdFactory messageIdFactory;
    private final SessionCookies sessionCookies;
    private final RecoveryCodeGenerator recoveryCodeGenerator = InjectorHolder.getInstance(RecoveryCodeGenerator.class);


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

        @Attribute(order = 600)
        default boolean generateRecoveryCodes() { return true; }
    }

    @Inject
    public PushRegNode(@Assisted Config config, CoreWrapper coreWrapper,
                       UserPushDeviceProfileManager userPushDeviceProfileManager,
                       PushNotificationService pushNotificationService,
                       SessionCookies sessionCookies,
                       MessageIdFactory messageIdFactory) {
        this.config = config;
        this.coreWrapper = coreWrapper;
        this.userPushDeviceProfileManager = userPushDeviceProfileManager;
        this.pushNotificationService = pushNotificationService;
        this.sessionCookies = sessionCookies;
        this.messageIdFactory = messageIdFactory;
    }


    private Callback createQRCodeCallback(PushDeviceSettings deviceProfile, AMIdentity id, String messageId,
                                          String challenge, String serverUrl, String realm)
            throws NodeProcessException {

        QRCallbackBuilder builder;
        try {
            builder = new QRCallbackBuilder().withUriScheme("pushauth")
                                             .withUriHost("push")
                                             .withUriPath("forgerock")
                                             .withUriPort(id.getName())
                                             .withCallbackIndex(0)
                                             .addUriQueryComponent(LOADBALANCER_DATA_QR_CODE_KEY,
                                                                   Base64url.encode(sessionCookies.getLBCookie()
                                                                                                  .getBytes()))
                                             .addUriQueryComponent(ISSUER_QR_CODE_KEY,
                                                                   Base64url.encode(config.issuer().getBytes()))
                                             .addUriQueryComponent(MESSAGE_ID_QR_CODE_KEY, messageId)
                                             .addUriQueryComponent(SHARED_SECRET_QR_CODE_KEY,
                                                                   Base64url.encode(org.forgerock.util.encode.Base64
                                                                                            .decode(deviceProfile
                                                                                                            .getSharedSecret())))
                                             .addUriQueryComponent(BGCOLOUR_QR_CODE_KEY, config.color())
                                             .addUriQueryComponent(CHALLENGE_QR_CODE_KEY, Base64url
                                                     .encode(org.forgerock.util.encode.Base64.decode(challenge)))
                                             .addUriQueryComponent(REG_QR_CODE_KEY, Base64url
                                                     .encode((serverUrl + "/json" +
                                                             pushNotificationService.getServiceAddressFor(realm,
                                                                                                          DefaultMessageTypes.REGISTER))
                                                                     .getBytes()))
                                             .addUriQueryComponent(AUTH_QR_CODE_KEY, Base64url
                                                     .encode((serverUrl + "/json" +
                                                             pushNotificationService.getServiceAddressFor(realm,
                                                                                                          DefaultMessageTypes.AUTHENTICATE))
                                                                     .getBytes()));
        } catch (PushNotificationException e) {
            logger.error("Unable to generate QR code");
            throw new NodeProcessException("Unable to generate QR code");
        }

        if (config.imgUrl() != null) {
            builder.addUriQueryComponent(IMG_QR_CODE_KEY, Base64url.encode(config.imgUrl().getBytes()));
        }

        return builder.build();
    }

    void setRecoveryCodesOnDevice(boolean generateRecoveryCodes, PushDeviceSettings device,
                                  JsonValue transientState) throws CodeException {
        //generate recovery codes
        if (generateRecoveryCodes) {
            logger.debug("creating recovery codes for device");
            List<String> codes = recoveryCodeGenerator.generateCodes(NUM_RECOVERY_CODES, Alphabet.ALPHANUMERIC,
                                                                     false);
            device.setRecoveryCodes(codes);
            transientState.put(RecoveryCodeDisplayNode.RECOVERY_CODE_KEY, codes);
            transientState.put(RecoveryCodeDisplayNode.RECOVERY_CODE_DEVICE_NAME, device.getDeviceName());
        }
    }


    private void saveDeviceDetailsUnderUserAccount(JsonValue deviceResponse, String username, String realm,
                                                   TreeContext context) throws CodeException {
        PushDeviceSettings newDeviceRegistrationProfile = new PushDeviceSettings();
        newDeviceRegistrationProfile.setDeviceName("Push Device");

        try {
            newDeviceRegistrationProfile.setUUID(context.sharedState.get(PUSH_UUID).asString());
            newDeviceRegistrationProfile.setSharedSecret(context.sharedState.get(PUSH_SHAREDSECRET).asString());
            newDeviceRegistrationProfile.setCommunicationId(deviceResponse.get(COMMUNICATION_ID).asString());
            newDeviceRegistrationProfile.setDeviceMechanismUID(deviceResponse.get(MECHANISM_UID).asString());
            newDeviceRegistrationProfile.setCommunicationType(deviceResponse.get(COMMUNICATION_TYPE).asString());
            newDeviceRegistrationProfile.setDeviceType(deviceResponse.get(DEVICE_TYPE).asString());
            newDeviceRegistrationProfile.setDeviceId(deviceResponse.get(DEVICE_ID).asString());
            newDeviceRegistrationProfile.setIssuer(config.issuer());
        } catch (NullPointerException npe) {
            logger.error("Blank value for necessary data from device response, {}", deviceResponse);
        }

        setRecoveryCodesOnDevice(config.generateRecoveryCodes(), newDeviceRegistrationProfile, context.transientState);

        try {
            userPushDeviceProfileManager.saveDeviceProfile(username, realm, newDeviceRegistrationProfile);
        } catch (DevicePersistenceException e) {
            logger.error("Unable to store device profile.");
        }
    }


    private Callback[] generateCallbacks(TreeContext context, PushDeviceSettings newDeviceRegistrationProfile,
                                         String messageId, String challenge) {
        String realm = context.sharedState.get(SharedStateConstants.REALM).asString();
        String username = context.sharedState.get(USERNAME).asString();
        AMIdentity userIdentity = coreWrapper.getIdentity(username, realm);

        Callback QRcallback;
        try {
            QRcallback = createQRCodeCallback(newDeviceRegistrationProfile, userIdentity, messageId, challenge,
                                              context.request.serverUrl, realm);
        } catch (NodeProcessException e) {
            return null;
        }

        PollingWaitCallback pollingWaitCallback = PollingWaitCallback.makeCallback()
                                                                     .withWaitTime(String.valueOf(config.timeout()))
                                                                     .build();

        return new Callback[]{QRcallback, pollingWaitCallback};
    }


    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        logger.debug("PushRegNode started.");
        String realm = context.sharedState.get(SharedStateConstants.REALM).asString();
        String username = context.sharedState.get(USERNAME).asString();


        Optional<PollingWaitCallback> pollingCallback = context.getCallback(PollingWaitCallback.class);
        if (pollingCallback.isPresent()) {
            if (!context.sharedState.isDefined(PUSH_MESSAGEID)) {
                logger.error("Unable to find push message ID in sharedState");
                throw new NodeProcessException("Unable to find push message ID");
            }

            String pushMessageId = context.sharedState.get(PUSH_MESSAGEID).asString();
            try {
                MessageId messageId = messageIdFactory.create(pushMessageId, realm);
                ClusterMessageHandler messageHandler = pushNotificationService.getMessageHandlers(realm).get(
                        messageId.getMessageType());
                if (messageHandler == null) {
                    logger.error(
                            "The push message corresponds to {} message type which is not registered in the {} realm",
                            messageId.getMessageType(), realm);
                    throw new NodeProcessException("Unknown message type");
                }
                MessageState state = messageHandler.check(messageId);

                JsonValue newSharedState = context.sharedState.copy();
                if (state == null) {
                    logger.error("The push message with ID {} has timed out", messageId.toString());
                    throw new NodeProcessException("Message timed out");
                }

                switch (state) {
                    case SUCCESS:
                        JsonValue pushContent = messageHandler.getContents(messageId);
                        messageHandler.delete(messageId);
                        if (pushContent != null) {
                            saveDeviceDetailsUnderUserAccount(pushContent, username, realm, context);
                            newSharedState.remove(PUSH_MESSAGEID);
                            newSharedState.remove(PUSH_SHAREDSECRET);
                            newSharedState.remove(PUSH_UUID);
                            newSharedState.remove(PUSH_CHALLENGE);
                            return goTo("success").replaceSharedState(newSharedState).replaceTransientState(
                                    context.transientState).build();
                        } else {
                            throw new NodeProcessException("Failed to save device to user profile");
                        }
                    case DENIED:
                        messageHandler.delete(messageId);
                        throw new NodeProcessException("App denied registration");
                    case UNKNOWN:
                        int attempts = context.sharedState.get(PUSH_RETRIES).asInteger();
                        if (attempts >= config.retries()) {
                            return goTo("timeout").build();
                        } else {

                            PushDeviceSettings
                                    newDeviceRegistrationProfile =
                                    userPushDeviceProfileManager.createDeviceProfile();
                            newDeviceRegistrationProfile.setUUID(newSharedState.get(PUSH_UUID).asString());
                            newDeviceRegistrationProfile.setSharedSecret(
                                    newSharedState.get(PUSH_SHAREDSECRET).asString());
                            String challenge = newSharedState.get(PUSH_CHALLENGE).asString();
                            String messageIdStr = newSharedState.get(PUSH_MESSAGEID).asString();
                            newSharedState.put(PUSH_RETRIES, attempts + 1);

                            Callback[] callbacks = generateCallbacks(context, newDeviceRegistrationProfile,
                                                                     messageIdStr, challenge);

                            if (callbacks != null) {
                                return send(callbacks)
                                        .replaceSharedState(newSharedState.put(PUSH_MESSAGEID, messageIdStr))
                                        .build();
                            }
                            logger.error("Unable to generate callbacks");
                            throw new NodeProcessException("Callbacks are null");
                        }
                    default:
                        throw new NodeProcessException("Unrecognized push message status: " + state);
                }
            } catch (PushNotificationException | CoreTokenException ex) {
                throw new NodeProcessException("An unexpected error occurred while verifying the push result", ex);
            } catch (CodeException e) {
                throw new NodeProcessException("Unable to create device profile from response data.", e);
            }

        } else {
            JsonValue newSharedState = context.sharedState.copy();

            PushDeviceSettings newDeviceRegistrationProfile = userPushDeviceProfileManager.createDeviceProfile();
            logger.error(newDeviceRegistrationProfile.toString());

            MessageId messageId = messageIdFactory.create(DefaultMessageTypes.REGISTER);

            String challenge = userPushDeviceProfileManager.createRandomBytes();

            Callback[] callbacks = generateCallbacks(context, newDeviceRegistrationProfile, messageId.toString(),
                                                     challenge);
            newSharedState.put(PUSH_UUID, newDeviceRegistrationProfile.getUUID());
            newSharedState.put(PUSH_SHAREDSECRET, newDeviceRegistrationProfile.getSharedSecret());
            newSharedState.put(PUSH_CHALLENGE, challenge);
            newSharedState.put(PUSH_MESSAGEID, messageId.toString());
            newSharedState.put(PUSH_RETRIES, 0);


            byte[] secret = Base64.decode(newDeviceRegistrationProfile.getSharedSecret());

            Set<Predicate> servicePredicates = new HashSet<>() {{
                add(new SignedJwtVerificationPredicate(secret, JWT));
                add(new PushMessageChallengeResponsePredicate(secret, challenge, JWT));
            }};

            try {
                PushNotificationService pushService = getPushNotificationService(realm);

                Set<Predicate> predicates = pushService.getMessagePredicatesFor(realm).get(
                        DefaultMessageTypes.REGISTER);
                if (predicates != null) {
                    servicePredicates.addAll(predicates);
                }

                pushService.getMessageDispatcher(realm).expectInCluster(messageId, servicePredicates);
            } catch (NotFoundException | PushNotificationException e) {
                logger.error("Unable to read service addresses for Push Notification Service.");
            } catch (CoreTokenException e) {
                logger.error("Unable to persist token in core token service.", e);
            } catch (NodeProcessException e) {
                logger.error("Unable to get push notification service");
            }

            if (callbacks != null) {
                return send(callbacks)
                        .replaceSharedState(newSharedState.put(PUSH_MESSAGEID, messageId.toString()))
                        .build();
            }
            logger.error("Unable to generate callbacks");
            throw new NodeProcessException("Callbacks are null");
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
