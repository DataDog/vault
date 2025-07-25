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
 * @interface PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest
 */
export interface PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest {
    /**
     * ACME request 'payload' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest
     */
    payload?: string;
    /**
     * ACME request 'protected' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest
     */
    _protected?: string;
    /**
     * ACME request 'signature' value
     * @type {string}
     * @memberof PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest
     */
    signature?: string;
}

/**
 * Check if a given object implements the PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest interface.
 */
export function instanceOfPkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest(value: object): value is PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest {
    return true;
}

export function PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequestFromJSON(json: any): PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest {
    return PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequestFromJSONTyped(json, false);
}

export function PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'payload': json['payload'] == null ? undefined : json['payload'],
        '_protected': json['protected'] == null ? undefined : json['protected'],
        'signature': json['signature'] == null ? undefined : json['signature'],
    };
}

export function PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequestToJSON(json: any): PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest {
    return PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequestToJSONTyped(json, false);
}

export function PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequestToJSONTyped(value?: PkiWriteIssuerIssuerRefExternalPolicyPolicyAcmeNewOrderRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'payload': value['payload'],
        'protected': value['_protected'],
        'signature': value['signature'],
    };
}

