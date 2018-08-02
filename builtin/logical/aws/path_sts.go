package aws

import (
	"context"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathSTS(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sts/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"ttl": &framework.FieldSchema{
				Type: framework.TypeDurationSecond,
				Description: `Lifetime of the token in seconds.
AWS documentation excerpt: The duration, in seconds, that the credentials
should remain valid. Acceptable durations for IAM user sessions range from 900
seconds (15 minutes) to 129600 seconds (36 hours), with 43200 seconds (12
hours) as the default. Sessions for AWS account owners are restricted to a
maximum of 3600 seconds (one hour). If the duration is longer than one hour,
the session for AWS account owners defaults to one hour.`,
				Default: 3600,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathSTSRead,
			logical.UpdateOperation: b.pathSTSRead,
		},

		HelpSynopsis:    pathSTSHelpSyn,
		HelpDescription: pathSTSHelpDesc,
	}
}

func (b *backend) pathSTSRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	ttl := int64(d.Get("ttl").(int))

	// Read the role config
	role, err := getRoleConfig(ctx, req, name)
	if err != nil {
		return nil, errwrap.Wrapf("error retrieving role: {{err}}", err)
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf(
			"Role '%s' not found", name)), nil
	}

	// Use sts:AssumeRole
	if role.ARN != "" {
		return b.assumeRole(
			ctx,
			req.Storage,
			req.DisplayName, name, role.ARN, role.ExternalID,
			ttl,
		)
	}
	// Use sts:GetFederationToken
	return b.secretTokenCreate(
		ctx,
		req.Storage,
		req.DisplayName, name, role.Policy,
		ttl,
	)
}

const pathSTSHelpSyn = `
Generate an access key pair + security token for a specific role.
`

const pathSTSHelpDesc = `
This path will generate a new, never before used key pair + security token for
accessing AWS. The IAM policy used to back this key pair will be
the "name" parameter. For example, if this backend is mounted at "aws",
then "aws/sts/deploy" would generate access keys for the "deploy" role.

Note, these credentials are instantiated using the AWS STS backend.

The access keys will have a lease associated with them, but revoking the lease
does not revoke the access keys.
`
