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
 * @interface SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest
 */
export interface SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest {
    /**
     * Mount of the secret to configure or read.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest
     */
    mount?: string;
    /**
     * Name of the secret to configure or read.
     * @type {string}
     * @memberof SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest
     */
    secretName?: string;
}

/**
 * Check if a given object implements the SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest interface.
 */
export function instanceOfSystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest(value: object): value is SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest {
    return true;
}

export function SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequestFromJSON(json: any): SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest {
    return SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequestFromJSONTyped(json, false);
}

export function SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'mount': json['mount'] == null ? undefined : json['mount'],
        'secretName': json['secret_name'] == null ? undefined : json['secret_name'],
    };
}

export function SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequestToJSON(json: any): SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest {
    return SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequestToJSONTyped(json, false);
}

export function SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequestToJSONTyped(value?: SystemWriteSyncDestinationsTypeNameAssociationsRemoveRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'mount': value['mount'],
        'secret_name': value['secretName'],
    };
}

