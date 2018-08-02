package aws

import (
	"context"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/logical"
)

func TestBackend_PathListRoles(t *testing.T) {
	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b := Backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	// Add new roles
	roleData := []map[string]interface{}{
		{"arn": "testarn"},
		{"arn": "testarn", "external_id": "deadbeef"},
		{"policy": `{"Version": "2012-10-17", "Statements": []}`},
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
	}

	for i := 1; i <= 10; i++ {
		roleReq.Path = "roles/testrole" + strconv.Itoa(i)
		roleReq.Data = roleData[i%len(roleData)]
		resp, err = b.HandleRequest(context.Background(), roleReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: role creation failed. resp:%#v\n err:%v", resp, err)
		}
	}

	// List roles
	for _, path := range []string{"roles", "roles/"} {
		t.Run("list "+path, func(tt *testing.T) {
			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ListOperation,
				Path:      path,
				Storage:   config.StorageView,
			})
			if err != nil || (resp != nil && resp.IsError()) {
				tt.Fatalf("bad: listing roles failed. resp:%#v\n err:%v", resp, err)
			}

			keys, ok := resp.Data["keys"]
			if !ok {
				tt.Fatalf("list returned no keys")
			}
			if len(keys.([]string)) != 10 {
				tt.Fatalf("failed to list all 10 roles")
			}
		})
	}

	// Read roles
	roleReq = &logical.Request{
		Operation: logical.ReadOperation,
		Storage:   config.StorageView,
	}

	for i := 1; i <= 10; i++ {
		roleName := "testrole" + strconv.Itoa(i)
		roleReq.Path = "roles/" + roleName
		resp, err = b.HandleRequest(context.Background(), roleReq)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("bad: role read failed. resp:%#v\n err:%v", resp, err)
		}

		expected := roleData[i%len(roleData)]
		for k, v := range expected {
			vother, ok := resp.Data[k]
			if !ok {
				t.Fatalf("role %s is missing expected key %s (response: %v)", roleName, k, *resp)
			}
			if v.(string) != vother.(string) {
				t.Fatalf("role %s key %s value mismatch (expected %s, got %s, response: %v)", roleName, k, v.(string), vother.(string), resp)
			}
		}
	}

}
