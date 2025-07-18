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
 * @interface SystemPatchSyncDestinationsAwsSmNameRequest
 */
export interface SystemPatchSyncDestinationsAwsSmNameRequest {
    /**
     * AWS access key ID to access the secrets manager.
     * @type {string}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    accessKeyId?: string;
    /**
     * Sets which IPv4 addresses Vault is allowed to connect to for syncing secrets.
     * @type {Array<string>}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    allowedIpv4Addresses?: Array<string>;
    /**
     * Sets which IPv6 addresses Vault is allowed to connect to for syncing secrets.
     * @type {Array<string>}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    allowedIpv6Addresses?: Array<string>;
    /**
     * Sets which port numbers Vault is allowed to connect through for syncing secrets.
     * @type {Array<string>}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    allowedPorts?: Array<string>;
    /**
     * Custom tags to set on the secret managed at the destination. Custom tags are merged with system tags.
     * @type {object}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    customTags?: object;
    /**
     * Allows all IP addresses and ports to be connected to for syncing secrets.
     * @type {boolean}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    disableStrictNetworking?: boolean;
    /**
     * Unique string used as a condition for extra security when assuming the AWS IAM role. Optional. Ignored if the role ARN is not set.
     * @type {string}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    externalId?: string;
    /**
     * Determines what level of information is synced as a distinct resource at the destination. Supports `secret-path` and `secret-key`.
     * @type {string}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    granularity?: string;
    /**
     * Asynchronously unsyncs all associated secrets with the destination then deletes the destination config.
     * @type {boolean}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    purge?: boolean;
    /**
     * AWS region where to manage secrets.
     * @type {string}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    region?: string;
    /**
     * AWS IAM role identifier Vault will assume when connecting to the Secrets Manager. Optional. Supports cross-account access.
     * @type {string}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    roleArn?: string;
    /**
     * AWS secret access key to access the secrets manager.
     * @type {string}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    secretAccessKey?: string;
    /**
     * Template describing how to generate external secret names. Supports a subset of the Go Template syntax.
     * @type {string}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    secretNameTemplate?: string;
    /**
     * List of custom tags to remove for patch requests. This field is ignored on create and update requests.
     * @type {Array<string>}
     * @memberof SystemPatchSyncDestinationsAwsSmNameRequest
     */
    tagsToRemove?: Array<string>;
}

/**
 * Check if a given object implements the SystemPatchSyncDestinationsAwsSmNameRequest interface.
 */
export function instanceOfSystemPatchSyncDestinationsAwsSmNameRequest(value: object): value is SystemPatchSyncDestinationsAwsSmNameRequest {
    return true;
}

export function SystemPatchSyncDestinationsAwsSmNameRequestFromJSON(json: any): SystemPatchSyncDestinationsAwsSmNameRequest {
    return SystemPatchSyncDestinationsAwsSmNameRequestFromJSONTyped(json, false);
}

export function SystemPatchSyncDestinationsAwsSmNameRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): SystemPatchSyncDestinationsAwsSmNameRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'accessKeyId': json['access_key_id'] == null ? undefined : json['access_key_id'],
        'allowedIpv4Addresses': json['allowed_ipv4_addresses'] == null ? undefined : json['allowed_ipv4_addresses'],
        'allowedIpv6Addresses': json['allowed_ipv6_addresses'] == null ? undefined : json['allowed_ipv6_addresses'],
        'allowedPorts': json['allowed_ports'] == null ? undefined : json['allowed_ports'],
        'customTags': json['custom_tags'] == null ? undefined : json['custom_tags'],
        'disableStrictNetworking': json['disable_strict_networking'] == null ? undefined : json['disable_strict_networking'],
        'externalId': json['external_id'] == null ? undefined : json['external_id'],
        'granularity': json['granularity'] == null ? undefined : json['granularity'],
        'purge': json['purge'] == null ? undefined : json['purge'],
        'region': json['region'] == null ? undefined : json['region'],
        'roleArn': json['role_arn'] == null ? undefined : json['role_arn'],
        'secretAccessKey': json['secret_access_key'] == null ? undefined : json['secret_access_key'],
        'secretNameTemplate': json['secret_name_template'] == null ? undefined : json['secret_name_template'],
        'tagsToRemove': json['tags_to_remove'] == null ? undefined : json['tags_to_remove'],
    };
}

export function SystemPatchSyncDestinationsAwsSmNameRequestToJSON(json: any): SystemPatchSyncDestinationsAwsSmNameRequest {
    return SystemPatchSyncDestinationsAwsSmNameRequestToJSONTyped(json, false);
}

export function SystemPatchSyncDestinationsAwsSmNameRequestToJSONTyped(value?: SystemPatchSyncDestinationsAwsSmNameRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'access_key_id': value['accessKeyId'],
        'allowed_ipv4_addresses': value['allowedIpv4Addresses'],
        'allowed_ipv6_addresses': value['allowedIpv6Addresses'],
        'allowed_ports': value['allowedPorts'],
        'custom_tags': value['customTags'],
        'disable_strict_networking': value['disableStrictNetworking'],
        'external_id': value['externalId'],
        'granularity': value['granularity'],
        'purge': value['purge'],
        'region': value['region'],
        'role_arn': value['roleArn'],
        'secret_access_key': value['secretAccessKey'],
        'secret_name_template': value['secretNameTemplate'],
        'tags_to_remove': value['tagsToRemove'],
    };
}

