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
 * @interface PkiTidyRequest
 */
export interface PkiTidyRequest {
    /**
     * The amount of time that must pass after creation that an account with no orders is marked revoked, and the amount of time after being marked revoked or deactivated.
     * @type {string}
     * @memberof PkiTidyRequest
     */
    acmeAccountSafetyBuffer?: string;
    /**
     * The amount of extra time that must have passed beyond issuer's expiration before it is removed from the backend storage. Defaults to 8760 hours (1 year).
     * @type {string}
     * @memberof PkiTidyRequest
     */
    issuerSafetyBuffer?: string;
    /**
     * The amount of time to wait between processing certificates. This allows operators to change the execution profile of tidy to take consume less resources by slowing down how long it takes to run. Note that the entire list of certificates will be stored in memory during the entire tidy operation, but resources to read/process/update existing entries will be spread out over a greater period of time. By default this is zero seconds.
     * @type {string}
     * @memberof PkiTidyRequest
     */
    pauseDuration?: string;
    /**
     * The amount of time that must pass from the cross-cluster revocation request being initiated to when it will be slated for removal. Setting this too low may remove valid revocation requests before the owning cluster has a chance to process them, especially if the cluster is offline.
     * @type {string}
     * @memberof PkiTidyRequest
     */
    revocationQueueSafetyBuffer?: string;
    /**
     * The amount of extra time that must have passed beyond certificate expiration before it is removed from the backend storage and/or revocation list. Defaults to 72 hours.
     * @type {string}
     * @memberof PkiTidyRequest
     */
    safetyBuffer?: string;
    /**
     * Set to true to enable tidying ACME accounts, orders and authorizations. ACME orders are tidied (deleted) safety_buffer after the certificate associated with them expires, or after the order and relevant authorizations have expired if no certificate was produced. Authorizations are tidied with the corresponding order. When a valid ACME Account is at least acme_account_safety_buffer old, and has no remaining orders associated with it, the account is marked as revoked. After another acme_account_safety_buffer has passed from the revocation or deactivation date, a revoked or deactivated ACME account is deleted.
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyAcme?: boolean;
    /**
     * Set to true to enable tidying up certificate metadata
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyCertMetadata?: boolean;
    /**
     * Set to true to enable tidying up the certificate store
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyCertStore?: boolean;
    /**
     * Set to true to enable tidying up the CMPv2 nonce store
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyCmpv2NonceStore?: boolean;
    /**
     * Set to true to enable tidying up the cross-cluster revoked certificate store. Only runs on the active primary node.
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyCrossClusterRevokedCerts?: boolean;
    /**
     * Set to true to automatically remove expired issuers past the issuer_safety_buffer. No keys will be removed as part of this operation.
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyExpiredIssuers?: boolean;
    /**
     * Set to true to move the legacy ca_bundle from /config/ca_bundle to /config/ca_bundle.bak. This prevents downgrades to pre-Vault 1.11 versions (as older PKI engines do not know about the new multi-issuer storage layout), but improves the performance on seal wrapped PKI mounts. This will only occur if at least issuer_safety_buffer time has occurred after the initial storage migration. This backup is saved in case of an issue in future migrations. Operators may consider removing it via sys/raw if they desire. The backup will be removed via a DELETE /root call, but note that this removes ALL issuers within the mount (and is thus not desirable in most operational scenarios).
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyMoveLegacyCaBundle?: boolean;
    /**
     * Deprecated; synonym for 'tidy_revoked_certs
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyRevocationList?: boolean;
    /**
     * Set to true to remove stale revocation queue entries that haven't been confirmed by any active cluster. Only runs on the active primary node
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyRevocationQueue?: boolean;
    /**
     * Set to true to validate issuer associations on revocation entries. This helps increase the performance of CRL building and OCSP responses.
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyRevokedCertIssuerAssociations?: boolean;
    /**
     * Set to true to expire all revoked and expired certificates, removing them both from the CRL and from storage. The CRL will be rotated if this causes any values to be removed.
     * @type {boolean}
     * @memberof PkiTidyRequest
     */
    tidyRevokedCerts?: boolean;
}

/**
 * Check if a given object implements the PkiTidyRequest interface.
 */
export function instanceOfPkiTidyRequest(value: object): value is PkiTidyRequest {
    return true;
}

export function PkiTidyRequestFromJSON(json: any): PkiTidyRequest {
    return PkiTidyRequestFromJSONTyped(json, false);
}

export function PkiTidyRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): PkiTidyRequest {
    if (json == null) {
        return json;
    }
    return {
        
        'acmeAccountSafetyBuffer': json['acme_account_safety_buffer'] == null ? undefined : json['acme_account_safety_buffer'],
        'issuerSafetyBuffer': json['issuer_safety_buffer'] == null ? undefined : json['issuer_safety_buffer'],
        'pauseDuration': json['pause_duration'] == null ? undefined : json['pause_duration'],
        'revocationQueueSafetyBuffer': json['revocation_queue_safety_buffer'] == null ? undefined : json['revocation_queue_safety_buffer'],
        'safetyBuffer': json['safety_buffer'] == null ? undefined : json['safety_buffer'],
        'tidyAcme': json['tidy_acme'] == null ? undefined : json['tidy_acme'],
        'tidyCertMetadata': json['tidy_cert_metadata'] == null ? undefined : json['tidy_cert_metadata'],
        'tidyCertStore': json['tidy_cert_store'] == null ? undefined : json['tidy_cert_store'],
        'tidyCmpv2NonceStore': json['tidy_cmpv2_nonce_store'] == null ? undefined : json['tidy_cmpv2_nonce_store'],
        'tidyCrossClusterRevokedCerts': json['tidy_cross_cluster_revoked_certs'] == null ? undefined : json['tidy_cross_cluster_revoked_certs'],
        'tidyExpiredIssuers': json['tidy_expired_issuers'] == null ? undefined : json['tidy_expired_issuers'],
        'tidyMoveLegacyCaBundle': json['tidy_move_legacy_ca_bundle'] == null ? undefined : json['tidy_move_legacy_ca_bundle'],
        'tidyRevocationList': json['tidy_revocation_list'] == null ? undefined : json['tidy_revocation_list'],
        'tidyRevocationQueue': json['tidy_revocation_queue'] == null ? undefined : json['tidy_revocation_queue'],
        'tidyRevokedCertIssuerAssociations': json['tidy_revoked_cert_issuer_associations'] == null ? undefined : json['tidy_revoked_cert_issuer_associations'],
        'tidyRevokedCerts': json['tidy_revoked_certs'] == null ? undefined : json['tidy_revoked_certs'],
    };
}

export function PkiTidyRequestToJSON(json: any): PkiTidyRequest {
    return PkiTidyRequestToJSONTyped(json, false);
}

export function PkiTidyRequestToJSONTyped(value?: PkiTidyRequest | null, ignoreDiscriminator: boolean = false): any {
    if (value == null) {
        return value;
    }

    return {
        
        'acme_account_safety_buffer': value['acmeAccountSafetyBuffer'],
        'issuer_safety_buffer': value['issuerSafetyBuffer'],
        'pause_duration': value['pauseDuration'],
        'revocation_queue_safety_buffer': value['revocationQueueSafetyBuffer'],
        'safety_buffer': value['safetyBuffer'],
        'tidy_acme': value['tidyAcme'],
        'tidy_cert_metadata': value['tidyCertMetadata'],
        'tidy_cert_store': value['tidyCertStore'],
        'tidy_cmpv2_nonce_store': value['tidyCmpv2NonceStore'],
        'tidy_cross_cluster_revoked_certs': value['tidyCrossClusterRevokedCerts'],
        'tidy_expired_issuers': value['tidyExpiredIssuers'],
        'tidy_move_legacy_ca_bundle': value['tidyMoveLegacyCaBundle'],
        'tidy_revocation_list': value['tidyRevocationList'],
        'tidy_revocation_queue': value['tidyRevocationQueue'],
        'tidy_revoked_cert_issuer_associations': value['tidyRevokedCertIssuerAssociations'],
        'tidy_revoked_certs': value['tidyRevokedCerts'],
    };
}

