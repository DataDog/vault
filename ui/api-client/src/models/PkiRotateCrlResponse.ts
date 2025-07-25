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
 * @interface PkiRotateCrlResponse
 */
export interface PkiRotateCrlResponse {
    /**
     * Whether rotation was successful
     * @type {boolean}
     * @memberof PkiRotateCrlResponse
     */
    success?: boolean;
}

/**
 * Check if a given object implements the PkiRotateCrlResponse interface.
 */
export function instanceOfPkiRotateCrlResponse(value: object): value is PkiRotateCrlResponse {
    return true;
}

export function PkiRotateCrlResponseFromJSON(json: any): PkiRotateCrlResponse {
    return PkiRotateCrlResponseFromJSONTyped(json, false);
}

export function PkiRotateCrlResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiRotateCrlResponse {
    if (json == null) {
        return json;
    }
    return {
        
        'success': json['success'] == null ? undefined : json['success'],
    };
}

export function PkiRotateCrlResponseToJSON(json: any): PkiRotateCrlResponse {
    return PkiRotateCrlResponseToJSONTyped(json, false);
}

export function PkiRotateCrlResponseToJSONTyped(value?: PkiRotateCrlResponse | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'success': value['success'],
    };
}

