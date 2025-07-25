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
exports.instanceOfGoogleCloudKmsEncryptRequest = instanceOfGoogleCloudKmsEncryptRequest;
exports.GoogleCloudKmsEncryptRequestFromJSON = GoogleCloudKmsEncryptRequestFromJSON;
exports.GoogleCloudKmsEncryptRequestFromJSONTyped = GoogleCloudKmsEncryptRequestFromJSONTyped;
exports.GoogleCloudKmsEncryptRequestToJSON = GoogleCloudKmsEncryptRequestToJSON;
exports.GoogleCloudKmsEncryptRequestToJSONTyped = GoogleCloudKmsEncryptRequestToJSONTyped;
/**
 * Check if a given object implements the GoogleCloudKmsEncryptRequest interface.
 */
function instanceOfGoogleCloudKmsEncryptRequest(value) {
    return true;
}
function GoogleCloudKmsEncryptRequestFromJSON(json) {
    return GoogleCloudKmsEncryptRequestFromJSONTyped(json, false);
}
function GoogleCloudKmsEncryptRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'additionalAuthenticatedData': json['additional_authenticated_data'] == null ? undefined : json['additional_authenticated_data'],
        'keyVersion': json['key_version'] == null ? undefined : json['key_version'],
        'plaintext': json['plaintext'] == null ? undefined : json['plaintext'],
    };
}
function GoogleCloudKmsEncryptRequestToJSON(json) {
    return GoogleCloudKmsEncryptRequestToJSONTyped(json, false);
}
function GoogleCloudKmsEncryptRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'additional_authenticated_data': value['additionalAuthenticatedData'],
        'key_version': value['keyVersion'],
        'plaintext': value['plaintext'],
    };
}
