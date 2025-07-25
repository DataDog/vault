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
/**
 * Check if a given object implements the TransitHashWithAlgorithmRequest interface.
 */
export function instanceOfTransitHashWithAlgorithmRequest(value) {
    return true;
}
export function TransitHashWithAlgorithmRequestFromJSON(json) {
    return TransitHashWithAlgorithmRequestFromJSONTyped(json, false);
}
export function TransitHashWithAlgorithmRequestFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'algorithm': json['algorithm'] == null ? undefined : json['algorithm'],
        'format': json['format'] == null ? undefined : json['format'],
        'input': json['input'] == null ? undefined : json['input'],
    };
}
export function TransitHashWithAlgorithmRequestToJSON(json) {
    return TransitHashWithAlgorithmRequestToJSONTyped(json, false);
}
export function TransitHashWithAlgorithmRequestToJSONTyped(value, ignoreDiscriminator = false) {
    if (value == null) {
        return value;
    }
    return {
        'algorithm': value['algorithm'],
        'format': value['format'],
        'input': value['input'],
    };
}
