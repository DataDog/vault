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
exports.instanceOfAwsGenerateStsCredentialsWithParametersRequest = instanceOfAwsGenerateStsCredentialsWithParametersRequest;
exports.AwsGenerateStsCredentialsWithParametersRequestFromJSON = AwsGenerateStsCredentialsWithParametersRequestFromJSON;
exports.AwsGenerateStsCredentialsWithParametersRequestFromJSONTyped = AwsGenerateStsCredentialsWithParametersRequestFromJSONTyped;
exports.AwsGenerateStsCredentialsWithParametersRequestToJSON = AwsGenerateStsCredentialsWithParametersRequestToJSON;
exports.AwsGenerateStsCredentialsWithParametersRequestToJSONTyped = AwsGenerateStsCredentialsWithParametersRequestToJSONTyped;
/**
 * Check if a given object implements the AwsGenerateStsCredentialsWithParametersRequest interface.
 */
function instanceOfAwsGenerateStsCredentialsWithParametersRequest(value) {
    return true;
}
function AwsGenerateStsCredentialsWithParametersRequestFromJSON(json) {
    return AwsGenerateStsCredentialsWithParametersRequestFromJSONTyped(json, false);
}
function AwsGenerateStsCredentialsWithParametersRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'mfaCode': json['mfa_code'] == null ? undefined : json['mfa_code'],
        'roleArn': json['role_arn'] == null ? undefined : json['role_arn'],
        'roleSessionName': json['role_session_name'] == null ? undefined : json['role_session_name'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
    };
}
function AwsGenerateStsCredentialsWithParametersRequestToJSON(json) {
    return AwsGenerateStsCredentialsWithParametersRequestToJSONTyped(json, false);
}
function AwsGenerateStsCredentialsWithParametersRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'mfa_code': value['mfaCode'],
        'role_arn': value['roleArn'],
        'role_session_name': value['roleSessionName'],
        'ttl': value['ttl'],
    };
}
