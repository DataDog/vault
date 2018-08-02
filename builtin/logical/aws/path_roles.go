package aws

import (
	"context"
	"errors"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type roleConfig struct {
	ARN        string `json:"arn,omitempty"`
	Policy     string `json:"policy,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
}

func (r *roleConfig) toMap() map[string]interface{} {
	ret := make(map[string]interface{})
	if r.ARN != "" {
		ret["arn"] = r.ARN
	}
	if r.Policy != "" {
		ret["policy"] = r.Policy
	}
	if r.ExternalID != "" {
		ret["external_id"] = r.ExternalID
	}
	return ret
}

func getRoleConfig(ctx context.Context, req *logical.Request, name string) (*roleConfig, error) {
	var cfg roleConfig

	// Try new path first
	entry, err := req.Storage.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry != nil {
		err = entry.DecodeJSON(&cfg)
		if err != nil {
			return nil, err
		}
		return &cfg, nil
	}

	// Fallback to previous implementation where the role was stored as a single string
	// into `policy/<name>`, holding either an ARN or an IAM policy document.
	entry, err = req.Storage.Get(ctx, "policy/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	val := string(entry.Value)
	if strings.HasPrefix(val, "arn:") {
		cfg.ARN = val
	} else {
		cfg.Policy = val
	}
	return &cfg, nil
}

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the policy",
			},

			"arn": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "ARN Reference to a managed policy or role to assume",
			},

			"external_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "External ID used for STS assume role",
			},

			"policy": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "IAM policy document",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: pathRolesDelete,
			logical.ReadOperation:   pathRolesRead,
			logical.UpdateOperation: pathRolesWrite,
		},

		HelpSynopsis:    pathRolesHelpSyn,
		HelpDescription: pathRolesHelpDesc,
	}
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	entriesV1, err := req.Storage.List(ctx, "policy/")
	if err != nil {
		return nil, err
	}
	if len(entriesV1) > 0 {
		entries = append(entries, entriesV1...)
	}

	return logical.ListResponse(entries), nil
}

func pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	err = req.Storage.Delete(ctx, "policy/"+d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := getRoleConfig(ctx, req, d.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: role.toMap(),
	}, nil
}

func pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	arn := d.Get("arn").(string)
	policy := d.Get("policy").(string)
	externalID := d.Get("external_id").(string)

	if arn == "" && policy == "" {
		return nil, errors.New("either policy or arn must be provided")
	}
	if arn != "" && policy != "" {
		return nil, errors.New("only one of policy or arn should be provided")
	}
	if policy != "" && externalID != "" {
		return nil, errors.New("external_id cannot be provided with policy")
	}

	// Write the role config into storage
	entry, err := logical.StorageEntryJSON("role/"+d.Get("name").(string), roleConfig{
		ARN:        arn,
		Policy:     policy,
		ExternalID: externalID,
	})
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, entry)
	return nil, err
}

const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRolesHelpSyn = `
Read, write and reference IAM policies that access keys can be made for.
`

const pathRolesHelpDesc = `
This path allows you to read and write roles that are used to
create access keys. These roles are associated with IAM policies that
map directly to the route to read the access keys. For example, if the
backend is mounted at "aws" and you create a role at "aws/roles/deploy"
then a user could request access credentials at "aws/creds/deploy".

You can either supply a user inline policy (via the policy argument), or
provide a reference to an existing AWS policy by supplying the full arn
reference (via the arn argument). Inline user policies written are normal
IAM policies. Vault will not attempt to parse these except to validate
that they're basic JSON. No validation is performed on arn references.

To validate the keys, attempt to read an access key after writing the policy.
`
