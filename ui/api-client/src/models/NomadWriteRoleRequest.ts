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
 * @interface NomadWriteRoleRequest
 */
export interface NomadWriteRoleRequest {
    /**
     * Boolean value describing if the token should be global or not. Defaults to false.
     * @type {boolean}
     * @memberof NomadWriteRoleRequest
     */
    global?: boolean;
    /**
     * Comma-separated string or list of policies as previously created in Nomad. Required for 'client' token.
     * @type {Array<string>}
     * @memberof NomadWriteRoleRequest
     */
    policies?: Array<string>;
    /**
     * Which type of token to create: 'client' or 'management'. If a 'management' token, the "policies" parameter is not required. Defaults to 'client'.
     * @type {string}
     * @memberof NomadWriteRoleRequest
     */
    type?: string;
}

/**
 * Check if a given object implements the NomadWriteRoleRequest interface.
 */
export function instanceOfNomadWriteRoleRequest(value: object): value is NomadWriteRoleRequest {
    return true;
}

export function NomadWriteRoleRequestFromJSON(json: any): NomadWriteRoleRequest {
    return NomadWriteRoleRequestFromJSONTyped(json, false);
}

export function NomadWriteRoleRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): NomadWriteRoleRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'global': json['global'] == null ? undefined : json['global'],
        'policies': json['policies'] == null ? undefined : json['policies'],
        'type': json['type'] == null ? undefined : json['type'],
    };
}

export function NomadWriteRoleRequestToJSON(json: any): NomadWriteRoleRequest {
    return NomadWriteRoleRequestToJSONTyped(json, false);
}

export function NomadWriteRoleRequestToJSONTyped(value?: NomadWriteRoleRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'global': value['global'],
        'policies': value['policies'],
        'type': value['type'],
    };
}

