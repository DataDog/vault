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
exports.instanceOfGoogleCloudEditServiceAccountsForRoleRequest = instanceOfGoogleCloudEditServiceAccountsForRoleRequest;
exports.GoogleCloudEditServiceAccountsForRoleRequestFromJSON = GoogleCloudEditServiceAccountsForRoleRequestFromJSON;
exports.GoogleCloudEditServiceAccountsForRoleRequestFromJSONTyped = GoogleCloudEditServiceAccountsForRoleRequestFromJSONTyped;
exports.GoogleCloudEditServiceAccountsForRoleRequestToJSON = GoogleCloudEditServiceAccountsForRoleRequestToJSON;
exports.GoogleCloudEditServiceAccountsForRoleRequestToJSONTyped = GoogleCloudEditServiceAccountsForRoleRequestToJSONTyped;
/**
 * Check if a given object implements the GoogleCloudEditServiceAccountsForRoleRequest interface.
 */
function instanceOfGoogleCloudEditServiceAccountsForRoleRequest(value) {
    return true;
}
function GoogleCloudEditServiceAccountsForRoleRequestFromJSON(json) {
    return GoogleCloudEditServiceAccountsForRoleRequestFromJSONTyped(json, false);
}
function GoogleCloudEditServiceAccountsForRoleRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'add': json['add'] == null ? undefined : json['add'],
        'remove': json['remove'] == null ? undefined : json['remove'],
    };
}
function GoogleCloudEditServiceAccountsForRoleRequestToJSON(json) {
    return GoogleCloudEditServiceAccountsForRoleRequestToJSONTyped(json, false);
}
function GoogleCloudEditServiceAccountsForRoleRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'add': value['add'],
        'remove': value['remove'],
    };
}
