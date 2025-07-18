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
exports.instanceOfLdapWriteUserRequest = instanceOfLdapWriteUserRequest;
exports.LdapWriteUserRequestFromJSON = LdapWriteUserRequestFromJSON;
exports.LdapWriteUserRequestFromJSONTyped = LdapWriteUserRequestFromJSONTyped;
exports.LdapWriteUserRequestToJSON = LdapWriteUserRequestToJSON;
exports.LdapWriteUserRequestToJSONTyped = LdapWriteUserRequestToJSONTyped;
/**
 * Check if a given object implements the LdapWriteUserRequest interface.
 */
function instanceOfLdapWriteUserRequest(value) {
    return true;
}
function LdapWriteUserRequestFromJSON(json) {
    return LdapWriteUserRequestFromJSONTyped(json, false);
}
function LdapWriteUserRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'groups': json['groups'] == null ? undefined : json['groups'],
        'policies': json['policies'] == null ? undefined : json['policies'],
    };
}
function LdapWriteUserRequestToJSON(json) {
    return LdapWriteUserRequestToJSONTyped(json, false);
}
function LdapWriteUserRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'groups': value['groups'],
        'policies': value['policies'],
    };
}
