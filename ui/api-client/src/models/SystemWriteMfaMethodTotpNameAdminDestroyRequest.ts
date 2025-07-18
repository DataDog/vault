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
 * @interface SystemWriteMfaMethodTotpNameAdminDestroyRequest
 */
export interface SystemWriteMfaMethodTotpNameAdminDestroyRequest {
    /**
     * Identifier of the entity from which the MFA method secret needs to be removed.
     * @type {string}
     * @memberof SystemWriteMfaMethodTotpNameAdminDestroyRequest
     */
    entityId?: string;
}

/**
 * Check if a given object implements the SystemWriteMfaMethodTotpNameAdminDestroyRequest interface.
 */
export function instanceOfSystemWriteMfaMethodTotpNameAdminDestroyRequest(value: object): value is SystemWriteMfaMethodTotpNameAdminDestroyRequest {
    return true;
}

export function SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSON(json: any): SystemWriteMfaMethodTotpNameAdminDestroyRequest {
    return SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSONTyped(json, false);
}

export function SystemWriteMfaMethodTotpNameAdminDestroyRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): SystemWriteMfaMethodTotpNameAdminDestroyRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'entityId': json['entity_id'] == null ? undefined : json['entity_id'],
    };
}

export function SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSON(json: any): SystemWriteMfaMethodTotpNameAdminDestroyRequest {
    return SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSONTyped(json, false);
}

export function SystemWriteMfaMethodTotpNameAdminDestroyRequestToJSONTyped(value?: SystemWriteMfaMethodTotpNameAdminDestroyRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'entity_id': value['entityId'],
    };
}

