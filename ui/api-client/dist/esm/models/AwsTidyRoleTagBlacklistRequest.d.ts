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
/**
 *
 * @export
 * @interface AwsTidyRoleTagBlacklistRequest
 */
export interface AwsTidyRoleTagBlacklistRequest {
    /**
     * The amount of extra time that must have passed beyond the roletag expiration, before it is removed from the backend storage.
     * @type {string}
     * @memberof AwsTidyRoleTagBlacklistRequest
     */
    safetyBuffer?: string;
}
/**
 * Check if a given object implements the AwsTidyRoleTagBlacklistRequest interface.
 */
export declare function instanceOfAwsTidyRoleTagBlacklistRequest(value: object): value is AwsTidyRoleTagBlacklistRequest;
export declare function AwsTidyRoleTagBlacklistRequestFromJSON(json: any): AwsTidyRoleTagBlacklistRequest;
export declare function AwsTidyRoleTagBlacklistRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): AwsTidyRoleTagBlacklistRequest;
export declare function AwsTidyRoleTagBlacklistRequestToJSON(json: any): AwsTidyRoleTagBlacklistRequest;
export declare function AwsTidyRoleTagBlacklistRequestToJSONTyped(value?: AwsTidyRoleTagBlacklistRequest | null, ignoreDiscriminator?: boolean): any;
