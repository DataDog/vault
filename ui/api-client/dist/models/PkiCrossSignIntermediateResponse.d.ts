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
 * @interface PkiCrossSignIntermediateResponse
 */
export interface PkiCrossSignIntermediateResponse {
    /**
     * Certificate signing request.
     * @type {string}
     * @memberof PkiCrossSignIntermediateResponse
     */
    csr?: string;
    /**
     * Id of the key.
     * @type {string}
     * @memberof PkiCrossSignIntermediateResponse
     */
    keyId?: string;
    /**
     * Generated private key.
     * @type {string}
     * @memberof PkiCrossSignIntermediateResponse
     */
    privateKey?: string;
    /**
     * Specifies the format used for marshaling the private key.
     * @type {string}
     * @memberof PkiCrossSignIntermediateResponse
     */
    privateKeyType?: string;
}
/**
 * Check if a given object implements the PkiCrossSignIntermediateResponse interface.
 */
export declare function instanceOfPkiCrossSignIntermediateResponse(value: object): value is PkiCrossSignIntermediateResponse;
export declare function PkiCrossSignIntermediateResponseFromJSON(json: any): PkiCrossSignIntermediateResponse;
export declare function PkiCrossSignIntermediateResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiCrossSignIntermediateResponse;
export declare function PkiCrossSignIntermediateResponseToJSON(json: any): PkiCrossSignIntermediateResponse;
export declare function PkiCrossSignIntermediateResponseToJSONTyped(value?: PkiCrossSignIntermediateResponse | null, ignoreDiscriminator?: boolean): any;
