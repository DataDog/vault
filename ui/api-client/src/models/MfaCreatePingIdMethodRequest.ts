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
 * @interface MfaCreatePingIdMethodRequest
 */
export interface MfaCreatePingIdMethodRequest {
    /**
     * The unique name identifier for this MFA method.
     * @type {string}
     * @memberof MfaCreatePingIdMethodRequest
     */
    methodName?: string;
    /**
     * The settings file provided by Ping, Base64-encoded. This must be a settings file suitable for third-party clients, not the PingID SDK or PingFederate.
     * @type {string}
     * @memberof MfaCreatePingIdMethodRequest
     */
    settingsFileBase64?: string;
    /**
     * A template string for mapping Identity names to MFA method names. Values to subtitute should be placed in {{}}. For example, "{{alias.name}}@example.com". Currently-supported mappings: alias.name: The name returned by the mount configured via the mount_accessor parameter If blank, the Alias's name field will be used as-is.
     * @type {string}
     * @memberof MfaCreatePingIdMethodRequest
     */
    usernameFormat?: string;
}

/**
 * Check if a given object implements the MfaCreatePingIdMethodRequest interface.
 */
export function instanceOfMfaCreatePingIdMethodRequest(value: object): value is MfaCreatePingIdMethodRequest {
    return true;
}

export function MfaCreatePingIdMethodRequestFromJSON(json: any): MfaCreatePingIdMethodRequest {
    return MfaCreatePingIdMethodRequestFromJSONTyped(json, false);
}

export function MfaCreatePingIdMethodRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): MfaCreatePingIdMethodRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'methodName': json['method_name'] == null ? undefined : json['method_name'],
        'settingsFileBase64': json['settings_file_base64'] == null ? undefined : json['settings_file_base64'],
        'usernameFormat': json['username_format'] == null ? undefined : json['username_format'],
    };
}

export function MfaCreatePingIdMethodRequestToJSON(json: any): MfaCreatePingIdMethodRequest {
    return MfaCreatePingIdMethodRequestToJSONTyped(json, false);
}

export function MfaCreatePingIdMethodRequestToJSONTyped(value?: MfaCreatePingIdMethodRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'method_name': value['methodName'],
        'settings_file_base64': value['settingsFileBase64'],
        'username_format': value['usernameFormat'],
    };
}

