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
exports.instanceOfPoliciesListAclPolicies3Response = instanceOfPoliciesListAclPolicies3Response;
exports.PoliciesListAclPolicies3ResponseFromJSON = PoliciesListAclPolicies3ResponseFromJSON;
exports.PoliciesListAclPolicies3ResponseFromJSONTyped = PoliciesListAclPolicies3ResponseFromJSONTyped;
exports.PoliciesListAclPolicies3ResponseToJSON = PoliciesListAclPolicies3ResponseToJSON;
exports.PoliciesListAclPolicies3ResponseToJSONTyped = PoliciesListAclPolicies3ResponseToJSONTyped;
/**
 * Check if a given object implements the PoliciesListAclPolicies3Response interface.
 */
function instanceOfPoliciesListAclPolicies3Response(value) {
    return true;
}
function PoliciesListAclPolicies3ResponseFromJSON(json) {
    return PoliciesListAclPolicies3ResponseFromJSONTyped(json, false);
}
function PoliciesListAclPolicies3ResponseFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'keys': json['keys'] == null ? undefined : json['keys'],
        'policies': json['policies'] == null ? undefined : json['policies'],
    };
}
function PoliciesListAclPolicies3ResponseToJSON(json) {
    return PoliciesListAclPolicies3ResponseToJSONTyped(json, false);
}
function PoliciesListAclPolicies3ResponseToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'keys': value['keys'],
        'policies': value['policies'],
    };
}
