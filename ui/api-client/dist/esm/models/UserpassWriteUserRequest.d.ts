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
 * @interface UserpassWriteUserRequest
 */
export interface UserpassWriteUserRequest {
    /**
     * Use "token_bound_cidrs" instead. If this and "token_bound_cidrs" are both specified, only "token_bound_cidrs" will be used.
     * @type {Array<string>}
     * @memberof UserpassWriteUserRequest
     * @deprecated
     */
    boundCidrs?: Array<string>;
    /**
     * Use "token_max_ttl" instead. If this and "token_max_ttl" are both specified, only "token_max_ttl" will be used.
     * @type {string}
     * @memberof UserpassWriteUserRequest
     * @deprecated
     */
    maxTtl?: string;
    /**
     * Password for this user.
     * @type {string}
     * @memberof UserpassWriteUserRequest
     */
    password?: string;
    /**
     * Pre-hashed password in bcrypt format for this user.
     * @type {string}
     * @memberof UserpassWriteUserRequest
     */
    passwordHash?: string;
    /**
     * Use "token_policies" instead. If this and "token_policies" are both specified, only "token_policies" will be used.
     * @type {Array<string>}
     * @memberof UserpassWriteUserRequest
     * @deprecated
     */
    policies?: Array<string>;
    /**
     * Comma separated string or JSON list of CIDR blocks. If set, specifies the blocks of IP addresses which are allowed to use the generated token.
     * @type {Array<string>}
     * @memberof UserpassWriteUserRequest
     */
    tokenBoundCidrs?: Array<string>;
    /**
     * If set, tokens created via this role carry an explicit maximum TTL. During renewal, the current maximum TTL values of the role and the mount are not checked for changes, and any updates to these values will have no effect on the token being renewed.
     * @type {string}
     * @memberof UserpassWriteUserRequest
     */
    tokenExplicitMaxTtl?: string;
    /**
     * The maximum lifetime of the generated token
     * @type {string}
     * @memberof UserpassWriteUserRequest
     */
    tokenMaxTtl?: string;
    /**
     * If true, the 'default' policy will not automatically be added to generated tokens
     * @type {boolean}
     * @memberof UserpassWriteUserRequest
     */
    tokenNoDefaultPolicy?: boolean;
    /**
     * The maximum number of times a token may be used, a value of zero means unlimited
     * @type {number}
     * @memberof UserpassWriteUserRequest
     */
    tokenNumUses?: number;
    /**
     * If set, tokens created via this role will have no max lifetime; instead, their renewal period will be fixed to this value. This takes an integer number of seconds, or a string duration (e.g. "24h").
     * @type {string}
     * @memberof UserpassWriteUserRequest
     */
    tokenPeriod?: string;
    /**
     * Comma-separated list of policies
     * @type {Array<string>}
     * @memberof UserpassWriteUserRequest
     */
    tokenPolicies?: Array<string>;
    /**
     * The initial ttl of the token to generate
     * @type {string}
     * @memberof UserpassWriteUserRequest
     */
    tokenTtl?: string;
    /**
     * The type of token to generate, service or batch
     * @type {string}
     * @memberof UserpassWriteUserRequest
     */
    tokenType?: string;
    /**
     * Use "token_ttl" instead. If this and "token_ttl" are both specified, only "token_ttl" will be used.
     * @type {string}
     * @memberof UserpassWriteUserRequest
     * @deprecated
     */
    ttl?: string;
}
/**
 * Check if a given object implements the UserpassWriteUserRequest interface.
 */
export declare function instanceOfUserpassWriteUserRequest(value: object): value is UserpassWriteUserRequest;
export declare function UserpassWriteUserRequestFromJSON(json: any): UserpassWriteUserRequest;
export declare function UserpassWriteUserRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): UserpassWriteUserRequest;
export declare function UserpassWriteUserRequestToJSON(json: any): UserpassWriteUserRequest;
export declare function UserpassWriteUserRequestToJSONTyped(value?: UserpassWriteUserRequest | null, ignoreDiscriminator?: boolean): any;
