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
 * @interface GoogleCloudWriteImpersonatedAccountRequest
 */
export interface GoogleCloudWriteImpersonatedAccountRequest {
    /**
     * Required. Email of the GCP service account to manage. Cannot be updated.
     * @type {string}
     * @memberof GoogleCloudWriteImpersonatedAccountRequest
     */
    serviceAccountEmail?: string;
    /**
     * List of OAuth scopes to assign to access tokens generated under this account.
     * @type {Array<string>}
     * @memberof GoogleCloudWriteImpersonatedAccountRequest
     */
    tokenScopes?: Array<string>;
    /**
     * Lifetime of the token for the impersonated account.
     * @type {string}
     * @memberof GoogleCloudWriteImpersonatedAccountRequest
     */
    ttl?: string;
}

/**
 * Check if a given object implements the GoogleCloudWriteImpersonatedAccountRequest interface.
 */
export function instanceOfGoogleCloudWriteImpersonatedAccountRequest(value: object): value is GoogleCloudWriteImpersonatedAccountRequest {
    return true;
}

export function GoogleCloudWriteImpersonatedAccountRequestFromJSON(json: any): GoogleCloudWriteImpersonatedAccountRequest {
    return GoogleCloudWriteImpersonatedAccountRequestFromJSONTyped(json, false);
}

export function GoogleCloudWriteImpersonatedAccountRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): GoogleCloudWriteImpersonatedAccountRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'serviceAccountEmail': json['service_account_email'] == null ? undefined : json['service_account_email'],
        'tokenScopes': json['token_scopes'] == null ? undefined : json['token_scopes'],
        'ttl': json['ttl'] == null ? undefined : json['ttl'],
    };
}

export function GoogleCloudWriteImpersonatedAccountRequestToJSON(json: any): GoogleCloudWriteImpersonatedAccountRequest {
    return GoogleCloudWriteImpersonatedAccountRequestToJSONTyped(json, false);
}

export function GoogleCloudWriteImpersonatedAccountRequestToJSONTyped(value?: GoogleCloudWriteImpersonatedAccountRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'service_account_email': value['serviceAccountEmail'],
        'token_scopes': value['tokenScopes'],
        'ttl': value['ttl'],
    };
}

