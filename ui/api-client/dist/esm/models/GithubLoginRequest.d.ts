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
 * @interface GithubLoginRequest
 */
export interface GithubLoginRequest {
    /**
     * GitHub personal API token
     * @type {string}
     * @memberof GithubLoginRequest
     */
    token?: string;
}
/**
 * Check if a given object implements the GithubLoginRequest interface.
 */
export declare function instanceOfGithubLoginRequest(value: object): value is GithubLoginRequest;
export declare function GithubLoginRequestFromJSON(json: any): GithubLoginRequest;
export declare function GithubLoginRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): GithubLoginRequest;
export declare function GithubLoginRequestToJSON(json: any): GithubLoginRequest;
export declare function GithubLoginRequestToJSONTyped(value?: GithubLoginRequest | null, ignoreDiscriminator?: boolean): any;
