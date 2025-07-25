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
 * @interface PkiWriteAcmeNewAccountRequest
 */
export interface PkiWriteAcmeNewAccountRequest {
    /**
     * ACME request 'payload' value
     * @type {string}
     * @memberof PkiWriteAcmeNewAccountRequest
     */
    payload?: string;
    /**
     * ACME request 'protected' value
     * @type {string}
     * @memberof PkiWriteAcmeNewAccountRequest
     */
    _protected?: string;
    /**
     * ACME request 'signature' value
     * @type {string}
     * @memberof PkiWriteAcmeNewAccountRequest
     */
    signature?: string;
}

/**
 * Check if a given object implements the PkiWriteAcmeNewAccountRequest interface.
 */
export function instanceOfPkiWriteAcmeNewAccountRequest(value: object): value is PkiWriteAcmeNewAccountRequest {
    return true;
}

export function PkiWriteAcmeNewAccountRequestFromJSON(json: any): PkiWriteAcmeNewAccountRequest {
    return PkiWriteAcmeNewAccountRequestFromJSONTyped(json, false);
}

export function PkiWriteAcmeNewAccountRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiWriteAcmeNewAccountRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'payload': json['payload'] == null ? undefined : json['payload'],
        '_protected': json['protected'] == null ? undefined : json['protected'],
        'signature': json['signature'] == null ? undefined : json['signature'],
    };
}

export function PkiWriteAcmeNewAccountRequestToJSON(json: any): PkiWriteAcmeNewAccountRequest {
    return PkiWriteAcmeNewAccountRequestToJSONTyped(json, false);
}

export function PkiWriteAcmeNewAccountRequestToJSONTyped(value?: PkiWriteAcmeNewAccountRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'payload': value['payload'],
        'protected': value['_protected'],
        'signature': value['signature'],
    };
}

