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

import { mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface SshVerifyOtpRequest
 */
export interface SshVerifyOtpRequest {
    /**
     * [Required] One-Time-Key that needs to be validated
     * @type {string}
     * @memberof SshVerifyOtpRequest
     */
    otp?: string;
}

/**
 * Check if a given object implements the SshVerifyOtpRequest interface.
 */
export function instanceOfSshVerifyOtpRequest(value: object): value is SshVerifyOtpRequest {
    return true;
}

export function SshVerifyOtpRequestFromJSON(json: any): SshVerifyOtpRequest {
    return SshVerifyOtpRequestFromJSONTyped(json, false);
}

export function SshVerifyOtpRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): SshVerifyOtpRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'otp': json['otp'] == null ? undefined : json['otp'],
    };
}

export function SshVerifyOtpRequestToJSON(json: any): SshVerifyOtpRequest {
    return SshVerifyOtpRequestToJSONTyped(json, false);
}

export function SshVerifyOtpRequestToJSONTyped(value?: SshVerifyOtpRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'otp': value['otp'],
    };
}

