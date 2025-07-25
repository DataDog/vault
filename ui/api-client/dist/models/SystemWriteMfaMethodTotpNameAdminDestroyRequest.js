"use strict";
/* tslint:disable */
/* eslint-disable */
/**
 * HashiCorp Vault API
 * HTTP API that gives you full access to Vault. All API routes are prefixed with `/v1/`.
 *
 * The version of the OpenAPI document: 1.21.0
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.instanceOfSystemWriteMfaMethodTotpNameAdminDestroyRequest = instanceOfSystemWriteMfaMethodTotpNameAdminDestroyRequest;
exports.SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSON = SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSON;
exports.SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSONTyped = SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSONTyped;
exports.SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSON = SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSON;
exports.SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSONTyped = SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSONTyped;
/**
 * Check if a given object implements the SystemWriteMfaMethodTotpNameAdminDestroyRequest interface.
 */
function instanceOfSystemWriteMfaMethodTotpNameAdminDestroyRequest(value) {
    return true;
}
function SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSON(json) {
    return SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSONTyped(json, false);
}
function SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'entityId': json['entity_id'] == null ? undefined : json['entity_id'],
    };
}
function SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSON(json) {
    return SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSONTyped(json, false);
}
function SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'entity_id': value['entityId'],
    };
}
