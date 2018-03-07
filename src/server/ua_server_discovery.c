/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */

#include "ua_server_internal.h"
#include "ua_client.h"

#ifdef UA_ENABLE_DISCOVERY

static UA_StatusCode
findEndpointForRegistration(const UA_EndpointDescription endpoints[], size_t endpointsSize,
                            const UA_SecurityPolicy *const supportedPolicies[], size_t supportedPoliciesSize,
                            UA_EndpointDescription *outEndpoint, const UA_SecurityPolicy **outPolicy) {
    const UA_String supportedTransports[] = {
        UA_STRING("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary")
    };
    size_t supportedTransportsSize = sizeof(supportedTransports) / sizeof(supportedTransports[0]);

    for(size_t policyIndex = 0; policyIndex < supportedPoliciesSize; ++policyIndex) {
        const UA_SecurityPolicy *policy = supportedPolicies[policyIndex];
        /* register server requires security */
        if(UA_String_equal(&policy->policyUri, &UA_SECURITY_POLICY_NONE_URI))
            continue;

        for(size_t endpointIndex = 0; endpointIndex < endpointsSize; ++endpointIndex) {
            const UA_EndpointDescription *endpoint = &endpoints[endpointIndex];

            if(!UA_String_equal(&endpoint->securityPolicyUri, &policy->policyUri))
                continue;

            UA_Boolean transportFound = UA_FALSE;
            for(size_t transportIndex = 0; transportIndex < supportedTransportsSize; ++transportIndex) {
                if(UA_String_equal(&endpoint->transportProfileUri, &supportedTransports[transportIndex])) {
                    transportFound = UA_TRUE;
                    break;
                }
            }
            if(!transportFound)
                continue;

            UA_Boolean tokenFound = UA_FALSE;
            for(size_t tokenIndex = 0; tokenIndex < endpoint->userIdentityTokensSize; ++tokenIndex) {
                const UA_UserTokenPolicy *userToken = &endpoint->userIdentityTokens[tokenIndex];
                if(userToken->tokenType == UA_USERTOKENTYPE_ANONYMOUS) {
                    tokenFound = UA_TRUE;
                    break;
                }
            }
            if(!tokenFound)
                continue;

            UA_StatusCode copyStatus = UA_EndpointDescription_copy(endpoint, outEndpoint);
            if(copyStatus != UA_STATUSCODE_GOOD) {
                return copyStatus;
            }
            *outPolicy = policy;
            return UA_STATUSCODE_GOOD;
        }
    }

    return UA_STATUSCODE_BADNOTFOUND;
}

static UA_StatusCode
register_server_with_discovery_server(UA_Server *server,
                                      const char* discoveryServerUrl,
                                      const UA_Boolean isUnregister,
                                      const char* semaphoreFilePath) {
    if(!discoveryServerUrl) {
        UA_LOG_ERROR(server->config.logger, UA_LOGCATEGORY_SERVER,
                     "No discovery server url provided");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Create the client */
    UA_ClientConfig clientConfig = UA_Server_getClientConfig();
    UA_Client *client = UA_Client_new(clientConfig);
    if(!client)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    /* Connect the client to get LDS' endpoints */
    UA_StatusCode retval = UA_Client_connect_securechannel(client, discoveryServerUrl);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(server->config.logger, UA_LOGCATEGORY_CLIENT,
                     "Connecting to the discovery server failed with statuscode %s",
                     UA_StatusCode_name(retval));
        UA_Client_disconnect(client);
        UA_Client_delete(client);
        return retval;
    }

    UA_EndpointDescription *endpointArray = NULL;
    size_t endpointArraySize = 0;
    UA_Client_getEndpointsInternal(client, &endpointArraySize, &endpointArray);

    UA_Client_disconnect(client);

    /* gather supported security policies from the server endpoints */
    size_t supportedPoliciesSize = server->config.endpointsSize;
    UA_SecurityPolicy **supportedPolicies = NULL;
    if(supportedPoliciesSize > 0) {
        supportedPolicies = (UA_SecurityPolicy **)UA_malloc(sizeof(UA_SecurityPolicy *) * supportedPoliciesSize);
    } else {
        /* Server has no endpoints */
        UA_Array_delete(endpointArray, endpointArraySize, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
        UA_Client_delete(client);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    if(supportedPolicies == NULL) {
        UA_Array_delete(endpointArray, endpointArraySize, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
        UA_Client_delete(client);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    for(size_t i = 0; i < server->config.endpointsSize; ++i) {
        supportedPolicies[i] = &server->config.endpoints[i].securityPolicy;
    }

    /* find a matching LDS endpoint */
    UA_EndpointDescription registerEndpoint;
    UA_EndpointDescription_init(&registerEndpoint);
    const UA_SecurityPolicy *policy = NULL;

    retval = findEndpointForRegistration(
        endpointArray,
        endpointArraySize,
        supportedPolicies,
        supportedPoliciesSize,
        &registerEndpoint,
        &policy
    );
    UA_Array_delete(endpointArray, endpointArraySize, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    UA_free(supportedPolicies);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_EndpointDescription_deleteMembers(&registerEndpoint);
        UA_Client_delete(client);
        return UA_STATUSCODE_BADSECURITYMODEREJECTED; // TODO: What is the best fitting return code?
    }

    /* connect again */
    char *urlCopy = (char *)UA_malloc(registerEndpoint.endpointUrl.length + 1);
    if(urlCopy == NULL) {
        UA_EndpointDescription_deleteMembers(&registerEndpoint);
        UA_Client_delete(client);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    memcpy(urlCopy, registerEndpoint.endpointUrl.data, registerEndpoint.endpointUrl.length);
    urlCopy[registerEndpoint.endpointUrl.length] = '\0';

    /* set up channel according to policy */
    UA_SecureChannel_init(&client->channel, policy, &registerEndpoint.serverCertificate);
    client->channel.securityMode = registerEndpoint.securityMode;
    UA_SecureChannel_generateLocalNonce(&client->channel);

    UA_EndpointDescription_deleteMembers(&registerEndpoint);

    retval = UA_Client_connect_securechannel(client, urlCopy);
    UA_free(urlCopy);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(server->config.logger, UA_LOGCATEGORY_CLIENT,
            "Connecting to the discovery server failed with statuscode %s",
            UA_StatusCode_name(retval));
        UA_Client_disconnect(client);
        client->channel.securityPolicy = NULL; // avoid delete of channelContext in UA_Client_delete
        UA_Client_delete(client);
        return retval;
    }

    UA_SecureChannel_generateNewKeys(&client->channel);

    /* Prepare the request. Do not cleanup the request after the service call,
     * as the members are stack-allocated or point into the server config. */
    UA_RegisterServer2Request request;
    UA_RegisterServer2Request_init(&request);
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;

    request.server.isOnline = !isUnregister;
    request.server.serverUri = server->config.applicationDescription.applicationUri;
    request.server.productUri = server->config.applicationDescription.productUri;
    request.server.serverType = server->config.applicationDescription.applicationType;
    request.server.gatewayServerUri = server->config.applicationDescription.gatewayServerUri;

    if(semaphoreFilePath) {
#ifdef UA_ENABLE_DISCOVERY_SEMAPHORE
        request.server.semaphoreFilePath =
            UA_STRING((char*)(uintptr_t)semaphoreFilePath); /* dirty cast */
#else
        UA_LOG_WARNING(server->config.logger, UA_LOGCATEGORY_CLIENT,
                       "Ignoring semaphore file path. open62541 not compiled "
                       "with UA_ENABLE_DISCOVERY_SEMAPHORE=ON");
#endif
    }

    request.server.serverNames = &server->config.applicationDescription.applicationName;
    request.server.serverNamesSize = 1;

    /* Copy the discovery urls from the server config and the network layers*/
    size_t config_discurls = server->config.applicationDescription.discoveryUrlsSize;
    size_t nl_discurls = server->config.networkLayersSize;
    size_t total_discurls = config_discurls + nl_discurls;
    UA_STACKARRAY(UA_String, urlsBuf, total_discurls);
    request.server.discoveryUrls = urlsBuf;
    if(request.server.discoveryUrls == NULL) {
        UA_Client_disconnect(client);
        client->channel.securityPolicy = NULL; // avoid delete of channelContext in UA_Client_delete
        UA_Client_delete(client);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    request.server.discoveryUrlsSize = total_discurls;

    for(size_t i = 0; i < config_discurls; ++i)
        request.server.discoveryUrls[i] = server->config.applicationDescription.discoveryUrls[i];

    /* TODO: Add nl only if discoveryUrl not already present */
    for(size_t i = 0; i < nl_discurls; ++i) {
        UA_ServerNetworkLayer *nl = &server->config.networkLayers[i];
        request.server.discoveryUrls[config_discurls + i] = nl->discoveryUrl;
    }

    UA_MdnsDiscoveryConfiguration mdnsConfig;
    UA_MdnsDiscoveryConfiguration_init(&mdnsConfig);

    request.discoveryConfigurationSize = 1;
    request.discoveryConfiguration = UA_ExtensionObject_new();
    UA_ExtensionObject_init(&request.discoveryConfiguration[0]);
    request.discoveryConfiguration[0].encoding = UA_EXTENSIONOBJECT_DECODED_NODELETE;
    request.discoveryConfiguration[0].content.decoded.type = &UA_TYPES[UA_TYPES_MDNSDISCOVERYCONFIGURATION];
    request.discoveryConfiguration[0].content.decoded.data = &mdnsConfig;

    mdnsConfig.mdnsServerName = server->config.mdnsServerName;
    mdnsConfig.serverCapabilities = server->config.serverCapabilities;
    mdnsConfig.serverCapabilitiesSize = server->config.serverCapabilitiesSize;

    // First try with RegisterServer2, if that isn't implemented, use RegisterServer
    UA_RegisterServer2Response response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_REGISTERSERVER2REQUEST],
                        &response, &UA_TYPES[UA_TYPES_REGISTERSERVER2RESPONSE]);

    UA_StatusCode serviceResult = response.responseHeader.serviceResult;
    UA_RegisterServer2Response_deleteMembers(&response);
    UA_ExtensionObject_delete(request.discoveryConfiguration);

    if(serviceResult == UA_STATUSCODE_BADNOTIMPLEMENTED ||
       serviceResult == UA_STATUSCODE_BADSERVICEUNSUPPORTED) {
        /* Try RegisterServer */
        UA_RegisterServerRequest request_fallback;
        UA_RegisterServerRequest_init(&request_fallback);
        /* Copy from RegisterServer2 request */
        request_fallback.requestHeader = request.requestHeader;
        request_fallback.server = request.server;

        UA_RegisterServerResponse response_fallback;

        __UA_Client_Service(client, &request_fallback,
                            &UA_TYPES[UA_TYPES_REGISTERSERVERREQUEST],
                            &response_fallback,
                            &UA_TYPES[UA_TYPES_REGISTERSERVERRESPONSE]);

        serviceResult = response_fallback.responseHeader.serviceResult;
        UA_RegisterServerResponse_deleteMembers(&response_fallback);
    }

    if(serviceResult != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(server->config.logger, UA_LOGCATEGORY_CLIENT,
                     "RegisterServer/RegisterServer2 failed with statuscode %s",
                     UA_StatusCode_name(serviceResult));
    }

    UA_Client_disconnect(client);
    client->channel.securityPolicy = NULL; // avoid delete of channelContext in UA_Client_delete
    UA_Client_delete(client);
    return serviceResult;
}

UA_StatusCode
UA_Server_register_discovery(UA_Server *server, const char* discoveryServerUrl,
                             const char* semaphoreFilePath) {
    return register_server_with_discovery_server(server, discoveryServerUrl,
                                                 UA_FALSE, semaphoreFilePath);
}

UA_StatusCode
UA_Server_unregister_discovery(UA_Server *server, const char* discoveryServerUrl) {
    return register_server_with_discovery_server(server, discoveryServerUrl,
                                                 UA_TRUE, NULL);
}

#endif /* UA_ENABLE_DISCOVERY */
