// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/vault/helper/timeutil"
	"github.com/hashicorp/vault/vault/activity"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
)

// equalActivityMonthRecords is a helper to sort the namespaces and mounts
// in activity.MonthRecord's, then compare their equality
func equalActivityMonthRecords(t *testing.T, expected, got *activity.MonthRecord) {
	t.Helper()
	sortNamespaces := func(namespaces []*activity.MonthlyNamespaceRecord) {
		sort.SliceStable(namespaces, func(i, j int) bool {
			return namespaces[i].NamespaceID < namespaces[j].NamespaceID
		})
		for _, namespace := range namespaces {
			sort.SliceStable(namespace.Mounts, func(i, j int) bool {
				return namespace.Mounts[i].MountPath < namespace.Mounts[j].MountPath
			})
		}
	}
	sortNamespaces(expected.Namespaces)
	sortNamespaces(expected.NewClients.Namespaces)
	sortNamespaces(got.Namespaces)
	sortNamespaces(got.NewClients.Namespaces)
	require.Equal(t, expected, got)
}

// Test_ActivityLog_ComputeCurrentMonthForBillingPeriodInternal test calls
// computeCurrentMonthForBillingPeriodInternal with the current month map having
// some overlap with the previous months. The test then verifies that the
// results have the correct number of entity, non-entity, and secret sync
// association clients. The test also calls
// computeCurrentMonthForBillingPeriodInternal with an empty current month map,
// and verifies that the results are all 0.
func Test_ActivityLog_ComputeCurrentMonthForBillingPeriodInternal(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	a := core.activityLog

	month := newProcessMonth()
	repeatedClientsIDsInMemory := make(map[string]struct{})
	// Below we register the entity, non-entity, and secret sync clients that
	// are seen in the current month

	// Let's add 2 entities exclusive to month 1 (clients 0,1),
	// 2 entities shared by month 1 and 2 (clients 10,11),
	// 2 entities shared by month 2 and 3 (clients 20,21), and
	// 2 entities exclusive to month 3 (30,31). Furthermore, we can add
	// 3 new entities (clients 40,41,42).
	entitiesStruct := map[string]struct{}{
		"client_0":  {},
		"client_1":  {},
		"client_10": {},
		"client_11": {},
		"client_20": {},
		"client_21": {},
		"client_30": {},
		"client_31": {},
	}
	newEntitiesStruct := map[string]struct{}{
		"client_40": {},
		"client_41": {},
		"client_42": {},
	}

	// repeated clients
	for id := range entitiesStruct {
		repeatedClientsIDsInMemory[id] = struct{}{}
		month.add(&activity.EntityRecord{ClientID: id, ClientType: entityActivityType})
	}

	// new clients
	for id := range newEntitiesStruct {
		month.add(&activity.EntityRecord{ClientID: id, ClientType: entityActivityType})
	}

	// We will add 3 nonentity clients from month 1 (clients 2,3,4),
	// 3 shared by months 1 and 2 (12,13,14),
	// 3 shared by months 2 and 3 (22,23,24), and
	// 3 exclusive to month 3 (32,33,34). We will also
	// add 4 new nonentity clients (43,44,45,46)
	nonEntitiesStruct := map[string]struct{}{
		"client_2":  {},
		"client_3":  {},
		"client_4":  {},
		"client_12": {},
		"client_13": {},
		"client_14": {},
		"client_22": {},
		"client_23": {},
		"client_24": {},
		"client_32": {},
		"client_33": {},
		"client_34": {},
	}

	newNonEntitiesStruct := map[string]struct{}{
		"client_43": {},
		"client_44": {},
		"client_45": {},
		"client_46": {},
	}

	// repeated non entity clients
	for id := range nonEntitiesStruct {
		repeatedClientsIDsInMemory[id] = struct{}{}
		month.add(&activity.EntityRecord{ClientID: id, ClientType: nonEntityTokenActivityType})
	}

	// new non entity clients
	for id := range newNonEntitiesStruct {
		month.add(&activity.EntityRecord{ClientID: id, ClientType: nonEntityTokenActivityType})
	}

	// secret syncs have 1 client from month 1 (5)
	// 1 shared by months 1 and 2 (15)
	// 1 shared by months 2 and 3 (25)
	// 2 exclusive to month 3 (35,36)
	// and 2 new clients (47,48)
	secretSyncStruct := map[string]struct{}{
		"client_5":  {},
		"client_15": {},
		"client_25": {},
		"client_35": {},
		"client_36": {},
	}

	newSecretSyncStruct := map[string]struct{}{
		"client_47": {},
		"client_48": {},
	}

	// repeated secret sync clients
	for id := range secretSyncStruct {
		repeatedClientsIDsInMemory[id] = struct{}{}
		month.add(&activity.EntityRecord{ClientID: id, ClientType: secretSyncActivityType})
	}

	// new secret sync clients
	for id := range newSecretSyncStruct {
		month.add(&activity.EntityRecord{ClientID: id, ClientType: secretSyncActivityType})
	}

	// store all repeated clients in in-memory client usage map
	a.SetClientIDsUsageInfo(repeatedClientsIDsInMemory)

	currentMonthClientsMap := make(map[int64]*processMonth, 1)

	// Technially I think currentMonthClientsMap should have the keys as
	// unix timestamps, but for the purposes of the unit test it doesn't
	// matter what the values actually are.
	currentMonthClientsMap[0] = month

	endTime := timeutil.StartOfMonth(time.Now())
	startTime := timeutil.MonthsPreviousTo(3, endTime)

	monthRecord, err := a.computeCurrentMonthForBillingPeriodInternal(currentMonthClientsMap, startTime, endTime)
	require.NoError(t, err)

	require.Equal(t, &activity.CountsRecord{
		EntityClients:    11,
		NonEntityClients: 16,
		SecretSyncs:      7,
	}, monthRecord.Counts)

	require.Equal(t, &activity.CountsRecord{
		EntityClients:    3,
		NonEntityClients: 4,
		SecretSyncs:      2,
	}, monthRecord.NewClients.Counts)

	// Attempt to compute current month when no records exist
	endTime = time.Now().UTC()
	startTime = timeutil.StartOfMonth(endTime)
	emptyClientsMap := make(map[int64]*processMonth, 0)
	monthRecord, err = a.computeCurrentMonthForBillingPeriodInternal(emptyClientsMap, startTime, endTime)
	require.NoError(t, err)

	require.Equal(t, &activity.CountsRecord{}, monthRecord.Counts)
	require.Equal(t, &activity.CountsRecord{}, monthRecord.NewClients.Counts)
}

// Test_ActivityLog_ComputeCurrentMonth_NamespaceMounts checks that current
// month counts are combined correctly with 3 previous months of data. The test
// checks a variety of scenarios with different mount and namespace values
func Test_ActivityLog_ComputeCurrentMonth_NamespaceMounts(t *testing.T) {
	testCases := []struct {
		name                          string
		repeatedClientsUntilLastMonth []*activity.EntityRecord
		currentMonthClients           []*activity.EntityRecord
		wantErr                       bool
		wantMonth                     *activity.MonthRecord
	}{
		{
			name: "no clients",
			wantMonth: &activity.MonthRecord{
				Counts:     &activity.CountsRecord{},
				Namespaces: []*activity.MonthlyNamespaceRecord{},
				NewClients: &activity.NewClientRecord{
					Counts:     &activity.CountsRecord{},
					Namespaces: []*activity.MonthlyNamespaceRecord{},
				},
			},
		},

		{
			// all the clients have been seen before
			// they're all on ns1/mount1
			name: "all repeated",
			repeatedClientsUntilLastMonth: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
			},
			currentMonthClients: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
			},
			wantMonth: &activity.MonthRecord{
				Counts: &activity.CountsRecord{
					EntityClients:    1,
					SecretSyncs:      1,
					NonEntityClients: 1,
					ACMEClients:      1,
				},
				Namespaces: []*activity.MonthlyNamespaceRecord{
					{
						NamespaceID: "ns1",
						Counts: &activity.CountsRecord{
							EntityClients:    1,
							NonEntityClients: 1,
							SecretSyncs:      1,
							ACMEClients:      1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									EntityClients:    1,
									NonEntityClients: 1,
									SecretSyncs:      1,
									ACMEClients:      1,
								},
							},
						},
					},
				},
				NewClients: &activity.NewClientRecord{
					Counts:     &activity.CountsRecord{},
					Namespaces: []*activity.MonthlyNamespaceRecord{},
				},
			},
		},
		{
			// all the clients have been seen before
			// they're all on ns1, but mounts 1-4
			name: "all repeated multiple mounts",
			repeatedClientsUntilLastMonth: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount2"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount3"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount4"},
			},
			currentMonthClients: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount2"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount3"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount4"},
			},
			wantMonth: &activity.MonthRecord{
				Counts: &activity.CountsRecord{
					EntityClients:    1,
					SecretSyncs:      1,
					NonEntityClients: 1,
					ACMEClients:      1,
				},
				Namespaces: []*activity.MonthlyNamespaceRecord{
					{
						NamespaceID: "ns1",
						Counts: &activity.CountsRecord{
							EntityClients:    1,
							NonEntityClients: 1,
							SecretSyncs:      1,
							ACMEClients:      1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									EntityClients: 1,
								},
							},
							{
								MountPath: "mount2",
								Counts: &activity.CountsRecord{
									NonEntityClients: 1,
								},
							},
							{
								MountPath: "mount3",
								Counts: &activity.CountsRecord{
									SecretSyncs: 1,
								},
							},
							{
								MountPath: "mount4",
								Counts: &activity.CountsRecord{
									ACMEClients: 1,
								},
							},
						},
					},
				},
				NewClients: &activity.NewClientRecord{
					Counts:     &activity.CountsRecord{},
					Namespaces: []*activity.MonthlyNamespaceRecord{},
				},
			},
		},
		{
			// all the clients have been seen before
			// they're on namespaces ns1-4
			name: "all repeated multiple namespaces",
			repeatedClientsUntilLastMonth: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns2", MountAccessor: "mount1"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns3", MountAccessor: "mount1"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns4", MountAccessor: "mount1"},
			},
			currentMonthClients: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns2", MountAccessor: "mount1"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns3", MountAccessor: "mount1"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns4", MountAccessor: "mount1"},
			},
			wantMonth: &activity.MonthRecord{
				Counts: &activity.CountsRecord{
					EntityClients:    1,
					SecretSyncs:      1,
					NonEntityClients: 1,
					ACMEClients:      1,
				},
				Namespaces: []*activity.MonthlyNamespaceRecord{
					{
						NamespaceID: "ns1",
						Counts: &activity.CountsRecord{
							EntityClients: 1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									EntityClients: 1,
								},
							},
						},
					},
					{
						NamespaceID: "ns2",
						Counts: &activity.CountsRecord{
							NonEntityClients: 1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									NonEntityClients: 1,
								},
							},
						},
					},
					{
						NamespaceID: "ns3",
						Counts: &activity.CountsRecord{
							SecretSyncs: 1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									SecretSyncs: 1,
								},
							},
						},
					},
					{
						NamespaceID: "ns4",
						Counts: &activity.CountsRecord{
							ACMEClients: 1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									ACMEClients: 1,
								},
							},
						},
					},
				},
				NewClients: &activity.NewClientRecord{
					Counts:     &activity.CountsRecord{},
					Namespaces: []*activity.MonthlyNamespaceRecord{},
				},
			},
		},
		{
			// 4 clients that have been seen before on namespaces 1-4
			// 4 new clients on namespaces 1-4
			name: "new clients multiple namespaces",
			repeatedClientsUntilLastMonth: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns2", MountAccessor: "mount1"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns3", MountAccessor: "mount1"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns4", MountAccessor: "mount1"},
			},
			currentMonthClients: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns2", MountAccessor: "mount1"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns3", MountAccessor: "mount1"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns4", MountAccessor: "mount1"},
				{ClientID: "new_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "new_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns2", MountAccessor: "mount1"},
				{ClientID: "new_3", ClientType: secretSyncActivityType, NamespaceID: "ns3", MountAccessor: "mount1"},
				{ClientID: "new_4", ClientType: ACMEActivityType, NamespaceID: "ns4", MountAccessor: "mount1"},
			},
			wantMonth: &activity.MonthRecord{
				Counts: &activity.CountsRecord{
					EntityClients:    2,
					SecretSyncs:      2,
					NonEntityClients: 2,
					ACMEClients:      2,
				},
				Namespaces: []*activity.MonthlyNamespaceRecord{
					{
						NamespaceID: "ns1",
						Counts: &activity.CountsRecord{
							EntityClients: 2,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									EntityClients: 2,
								},
							},
						},
					},
					{
						NamespaceID: "ns2",
						Counts: &activity.CountsRecord{
							NonEntityClients: 2,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									NonEntityClients: 2,
								},
							},
						},
					},
					{
						NamespaceID: "ns3",
						Counts: &activity.CountsRecord{
							SecretSyncs: 2,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									SecretSyncs: 2,
								},
							},
						},
					},
					{
						NamespaceID: "ns4",
						Counts: &activity.CountsRecord{
							ACMEClients: 2,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									ACMEClients: 2,
								},
							},
						},
					},
				},
				NewClients: &activity.NewClientRecord{
					Counts: &activity.CountsRecord{
						EntityClients:    1,
						NonEntityClients: 1,
						SecretSyncs:      1,
						ACMEClients:      1,
					},
					Namespaces: []*activity.MonthlyNamespaceRecord{
						{
							NamespaceID: "ns1",
							Counts: &activity.CountsRecord{
								EntityClients: 1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										EntityClients: 1,
									},
								},
							},
						},
						{
							NamespaceID: "ns2",
							Counts: &activity.CountsRecord{
								NonEntityClients: 1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										NonEntityClients: 1,
									},
								},
							},
						},
						{
							NamespaceID: "ns3",
							Counts: &activity.CountsRecord{
								SecretSyncs: 1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										SecretSyncs: 1,
									},
								},
							},
						},
						{
							NamespaceID: "ns4",
							Counts: &activity.CountsRecord{
								ACMEClients: 1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										ACMEClients: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// 4 clients that have been seen before on ns1/mount1-4
			// 4 new clients on ns1/mount1-4
			name: "new clients multiple mounts",
			repeatedClientsUntilLastMonth: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount2"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount3"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount4"},
			},
			currentMonthClients: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount2"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount3"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount4"},
				{ClientID: "new_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "new_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount2"},
				{ClientID: "new_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount3"},
				{ClientID: "new_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount4"},
			},
			wantMonth: &activity.MonthRecord{
				Counts: &activity.CountsRecord{
					EntityClients:    2,
					SecretSyncs:      2,
					NonEntityClients: 2,
					ACMEClients:      2,
				},
				Namespaces: []*activity.MonthlyNamespaceRecord{
					{
						NamespaceID: "ns1",
						Counts: &activity.CountsRecord{
							EntityClients:    2,
							NonEntityClients: 2,
							SecretSyncs:      2,
							ACMEClients:      2,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									EntityClients: 2,
								},
							},
							{
								MountPath: "mount2",
								Counts: &activity.CountsRecord{
									NonEntityClients: 2,
								},
							},
							{
								MountPath: "mount3",
								Counts: &activity.CountsRecord{
									SecretSyncs: 2,
								},
							},
							{
								MountPath: "mount4",
								Counts: &activity.CountsRecord{
									ACMEClients: 2,
								},
							},
						},
					},
				},
				NewClients: &activity.NewClientRecord{
					Counts: &activity.CountsRecord{
						EntityClients:    1,
						NonEntityClients: 1,
						SecretSyncs:      1,
						ACMEClients:      1,
					},
					Namespaces: []*activity.MonthlyNamespaceRecord{
						{
							NamespaceID: "ns1",
							Counts: &activity.CountsRecord{
								EntityClients:    1,
								NonEntityClients: 1,
								SecretSyncs:      1,
								ACMEClients:      1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										EntityClients: 1,
									},
								},
								{
									MountPath: "mount2",
									Counts: &activity.CountsRecord{
										NonEntityClients: 1,
									},
								},
								{
									MountPath: "mount3",
									Counts: &activity.CountsRecord{
										SecretSyncs: 1,
									},
								},
								{
									MountPath: "mount4",
									Counts: &activity.CountsRecord{
										ACMEClients: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// 4 clients that have been seen before on ns1/mount1-4
			// 4 new clients on ns1/mount5-6
			name: "new clients new mounts",
			repeatedClientsUntilLastMonth: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount2"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount3"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount4"},
			},
			currentMonthClients: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount2"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount3"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount4"},
				{ClientID: "new_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount5"},
				{ClientID: "new_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount6"},
				{ClientID: "new_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount7"},
				{ClientID: "new_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount8"},
			},
			wantMonth: &activity.MonthRecord{
				Counts: &activity.CountsRecord{
					EntityClients:    2,
					SecretSyncs:      2,
					NonEntityClients: 2,
					ACMEClients:      2,
				},
				Namespaces: []*activity.MonthlyNamespaceRecord{
					{
						NamespaceID: "ns1",
						Counts: &activity.CountsRecord{
							EntityClients:    2,
							NonEntityClients: 2,
							SecretSyncs:      2,
							ACMEClients:      2,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									EntityClients: 1,
								},
							},
							{
								MountPath: "mount2",
								Counts: &activity.CountsRecord{
									NonEntityClients: 1,
								},
							},
							{
								MountPath: "mount3",
								Counts: &activity.CountsRecord{
									SecretSyncs: 1,
								},
							},
							{
								MountPath: "mount4",
								Counts: &activity.CountsRecord{
									ACMEClients: 1,
								},
							},
							{
								MountPath: "mount5",
								Counts: &activity.CountsRecord{
									EntityClients: 1,
								},
							},
							{
								MountPath: "mount6",
								Counts: &activity.CountsRecord{
									NonEntityClients: 1,
								},
							},
							{
								MountPath: "mount7",
								Counts: &activity.CountsRecord{
									SecretSyncs: 1,
								},
							},
							{
								MountPath: "mount8",
								Counts: &activity.CountsRecord{
									ACMEClients: 1,
								},
							},
						},
					},
				},
				NewClients: &activity.NewClientRecord{
					Counts: &activity.CountsRecord{
						EntityClients:    1,
						NonEntityClients: 1,
						SecretSyncs:      1,
						ACMEClients:      1,
					},
					Namespaces: []*activity.MonthlyNamespaceRecord{
						{
							NamespaceID: "ns1",
							Counts: &activity.CountsRecord{
								EntityClients:    1,
								NonEntityClients: 1,
								SecretSyncs:      1,
								ACMEClients:      1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount5",
									Counts: &activity.CountsRecord{
										EntityClients: 1,
									},
								},
								{
									MountPath: "mount6",
									Counts: &activity.CountsRecord{
										NonEntityClients: 1,
									},
								},
								{
									MountPath: "mount7",
									Counts: &activity.CountsRecord{
										SecretSyncs: 1,
									},
								},
								{
									MountPath: "mount8",
									Counts: &activity.CountsRecord{
										ACMEClients: 1,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// 4 clients that have been seen before on ns1
			// 4 clients that are new on ns2-5
			name: "new clients new namespaces",
			repeatedClientsUntilLastMonth: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
			},
			currentMonthClients: []*activity.EntityRecord{
				{ClientID: "client_1", ClientType: entityActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_3", ClientType: secretSyncActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "client_4", ClientType: ACMEActivityType, NamespaceID: "ns1", MountAccessor: "mount1"},
				{ClientID: "new_1", ClientType: entityActivityType, NamespaceID: "ns2", MountAccessor: "mount1"},
				{ClientID: "new_2", ClientType: nonEntityTokenActivityType, NamespaceID: "ns3", MountAccessor: "mount1"},
				{ClientID: "new_3", ClientType: secretSyncActivityType, NamespaceID: "ns4", MountAccessor: "mount1"},
				{ClientID: "new_4", ClientType: ACMEActivityType, NamespaceID: "ns5", MountAccessor: "mount1"},
			},
			wantMonth: &activity.MonthRecord{
				Counts: &activity.CountsRecord{
					EntityClients:    2,
					SecretSyncs:      2,
					NonEntityClients: 2,
					ACMEClients:      2,
				},
				Namespaces: []*activity.MonthlyNamespaceRecord{
					{
						NamespaceID: "ns1",
						Counts: &activity.CountsRecord{
							EntityClients:    1,
							NonEntityClients: 1,
							SecretSyncs:      1,
							ACMEClients:      1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									EntityClients:    1,
									NonEntityClients: 1,
									SecretSyncs:      1,
									ACMEClients:      1,
								},
							},
						},
					},
					{
						NamespaceID: "ns2",
						Counts: &activity.CountsRecord{
							EntityClients: 1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									EntityClients: 1,
								},
							},
						},
					},
					{
						NamespaceID: "ns3",
						Counts: &activity.CountsRecord{
							NonEntityClients: 1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									NonEntityClients: 1,
								},
							},
						},
					},
					{
						NamespaceID: "ns4",
						Counts: &activity.CountsRecord{
							SecretSyncs: 1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									SecretSyncs: 1,
								},
							},
						},
					},

					{
						NamespaceID: "ns5",
						Counts: &activity.CountsRecord{
							ACMEClients: 1,
						},
						Mounts: []*activity.MountRecord{
							{
								MountPath: "mount1",
								Counts: &activity.CountsRecord{
									ACMEClients: 1,
								},
							},
						},
					},
				},
				NewClients: &activity.NewClientRecord{
					Counts: &activity.CountsRecord{
						EntityClients:    1,
						NonEntityClients: 1,
						SecretSyncs:      1,
						ACMEClients:      1,
					},
					Namespaces: []*activity.MonthlyNamespaceRecord{
						{
							NamespaceID: "ns2",
							Counts: &activity.CountsRecord{
								EntityClients: 1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										EntityClients: 1,
									},
								},
							},
						},
						{
							NamespaceID: "ns3",
							Counts: &activity.CountsRecord{
								NonEntityClients: 1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										NonEntityClients: 1,
									},
								},
							},
						},
						{
							NamespaceID: "ns4",
							Counts: &activity.CountsRecord{
								SecretSyncs: 1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										SecretSyncs: 1,
									},
								},
							},
						},
						{
							NamespaceID: "ns5",
							Counts: &activity.CountsRecord{
								ACMEClients: 1,
							},
							Mounts: []*activity.MountRecord{
								{
									MountPath: "mount1",
									Counts: &activity.CountsRecord{
										ACMEClients: 1,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			core, _, _ := TestCoreUnsealed(t)
			a := core.activityLog

			// add repeated clients seen till last month to in-memory map
			repeatedClients := make(map[string]struct{})
			for _, c := range tc.repeatedClientsUntilLastMonth {
				repeatedClients[c.ClientID] = struct{}{}
			}
			a.SetClientIDsUsageInfo(repeatedClients)

			month := newProcessMonth()
			for _, c := range tc.currentMonthClients {
				month.add(c)
			}
			endTime := timeutil.StartOfMonth(time.Now())
			startTime := timeutil.MonthsPreviousTo(3, endTime)
			currentMonth := make(map[int64]*processMonth)
			currentMonth[0] = month
			monthRecord, err := a.computeCurrentMonthForBillingPeriodInternal(currentMonth, startTime, endTime)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			correctMountPaths := func(namespaces []*activity.MonthlyNamespaceRecord) {
				for _, ns := range namespaces {
					for _, mount := range ns.Mounts {
						mount.MountPath = fmt.Sprintf(DeletedMountFmt, mount.MountPath)
					}
				}
			}
			tc.wantMonth.Timestamp = timeutil.StartOfMonth(endTime).Unix()
			correctMountPaths(tc.wantMonth.Namespaces)
			correctMountPaths(tc.wantMonth.NewClients.Namespaces)
			equalActivityMonthRecords(t, tc.wantMonth, monthRecord)
		})
	}
}

// writeEntitySegment writes a single segment file with the given time and index for an entity
func writeEntitySegment(t *testing.T, core *Core, ts time.Time, index int, item *activity.EntityActivityLog) {
	t.Helper()
	protoItem, err := proto.Marshal(item)
	require.NoError(t, err)
	WriteToStorage(t, core, makeSegmentPath(t, activityEntityBasePath, ts, index), protoItem)
}

// writeTokenSegment writes a single segment file with the given time and index for a token
func writeTokenSegment(t *testing.T, core *Core, ts time.Time, index int, item *activity.TokenCount) {
	t.Helper()
	protoItem, err := proto.Marshal(item)
	require.NoError(t, err)
	WriteToStorage(t, core, makeSegmentPath(t, activityTokenBasePath, ts, index), protoItem)
}

// makeSegmentPath formats the path for a segment at a particular time and index
func makeSegmentPath(t *testing.T, typ string, ts time.Time, index int) string {
	t.Helper()
	return fmt.Sprintf("%s%s%d/%d", ActivityPrefix, typ, ts.Unix(), index)
}

// TestSegmentFileReader_BadData verifies that the reader returns errors when the data is unable to be parsed
// However, the next time that Read*() is called, the reader should still progress and be able to then return any
// valid data without errors
func TestSegmentFileReader_BadData(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	now := time.Now()

	// write bad data that won't be able to be unmarshaled at index 0
	WriteToStorage(t, core, makeSegmentPath(t, activityTokenBasePath, now, 0), []byte("fake data"))
	WriteToStorage(t, core, makeSegmentPath(t, activityEntityBasePath, now, 0), []byte("fake data"))

	// write entity at index 1
	entity := &activity.EntityActivityLog{Clients: []*activity.EntityRecord{
		{
			ClientID: "id",
		},
	}}
	writeEntitySegment(t, core, now, 1, entity)

	// write token at index 1
	token := &activity.TokenCount{CountByNamespaceID: map[string]uint64{
		"ns": 1,
	}}
	writeTokenSegment(t, core, now, 1, token)
	reader, err := core.activityLog.NewSegmentFileReader(context.Background(), now)
	require.NoError(t, err)

	// first the bad entity is read, which returns an error
	_, err = reader.ReadEntity(context.Background())
	require.Error(t, err)
	// then, the reader can read the good entity at index 1
	gotEntity, err := reader.ReadEntity(context.Background())
	require.True(t, proto.Equal(gotEntity, entity))
	require.Nil(t, err)

	// the bad token causes an error
	_, err = reader.ReadToken(context.Background())
	require.Error(t, err)
	// but the good token is able to be read
	gotToken, err := reader.ReadToken(context.Background())
	require.True(t, proto.Equal(gotToken, token))
	require.Nil(t, err)
}

// TestSegmentFileReader_MissingData verifies that the segment file reader will skip over missing segment paths without
// errorring until it is able to find a valid segment path
func TestSegmentFileReader_MissingData(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	now := time.Now()
	// write entities and tokens at indexes 0, 1, 2
	for i := 0; i < 3; i++ {
		WriteToStorage(t, core, makeSegmentPath(t, activityTokenBasePath, now, i), []byte("fake data"))
		WriteToStorage(t, core, makeSegmentPath(t, activityEntityBasePath, now, i), []byte("fake data"))

	}
	// write entity at index 3
	entity := &activity.EntityActivityLog{Clients: []*activity.EntityRecord{
		{
			ClientID: "id",
		},
	}}
	writeEntitySegment(t, core, now, 3, entity)
	// write token at index 3
	token := &activity.TokenCount{CountByNamespaceID: map[string]uint64{
		"ns": 1,
	}}
	writeTokenSegment(t, core, now, 3, token)
	reader, err := core.activityLog.NewSegmentFileReader(context.Background(), now)
	require.NoError(t, err)

	// delete the indexes 0, 1, 2
	for i := 0; i < 3; i++ {
		require.NoError(t, core.barrier.Delete(context.Background(), makeSegmentPath(t, activityTokenBasePath, now, i)))
		require.NoError(t, core.barrier.Delete(context.Background(), makeSegmentPath(t, activityEntityBasePath, now, i)))
	}

	// we expect the reader to only return the data at index 3, and then be done
	gotEntity, err := reader.ReadEntity(context.Background())
	require.NoError(t, err)
	require.True(t, proto.Equal(gotEntity, entity))
	_, err = reader.ReadEntity(context.Background())
	require.Equal(t, err, io.EOF)

	gotToken, err := reader.ReadToken(context.Background())
	require.NoError(t, err)
	require.True(t, proto.Equal(gotToken, token))
	_, err = reader.ReadToken(context.Background())
	require.Equal(t, err, io.EOF)
}

// TestSegmentFileReader_NoData verifies that the reader return io.EOF when there is no data
func TestSegmentFileReader_NoData(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	now := time.Now()
	reader, err := core.activityLog.NewSegmentFileReader(context.Background(), now)
	require.NoError(t, err)
	entity, err := reader.ReadEntity(context.Background())
	require.Nil(t, entity)
	require.Equal(t, err, io.EOF)
	token, err := reader.ReadToken(context.Background())
	require.Nil(t, token)
	require.Equal(t, err, io.EOF)
}

// TestSegmentFileReader verifies that the reader iterates through all segments paths in ascending order and returns
// io.EOF when it's done
func TestSegmentFileReader(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	now := time.Now()
	entities := make([]*activity.EntityActivityLog, 0, 3)
	tokens := make([]*activity.TokenCount, 0, 3)

	// write 3 entity segment pieces and 3 token segment pieces
	for i := 0; i < 3; i++ {
		entity := &activity.EntityActivityLog{Clients: []*activity.EntityRecord{
			{
				ClientID: fmt.Sprintf("id-%d", i),
			},
		}}
		token := &activity.TokenCount{CountByNamespaceID: map[string]uint64{
			fmt.Sprintf("ns-%d", i): uint64(i),
		}}
		writeEntitySegment(t, core, now, i, entity)
		writeTokenSegment(t, core, now, i, token)
		entities = append(entities, entity)
		tokens = append(tokens, token)
	}

	reader, err := core.activityLog.NewSegmentFileReader(context.Background(), now)
	require.NoError(t, err)

	gotEntities := make([]*activity.EntityActivityLog, 0, 3)
	gotTokens := make([]*activity.TokenCount, 0, 3)

	// read the entities from the reader
	for entity, err := reader.ReadEntity(context.Background()); !errors.Is(err, io.EOF); entity, err = reader.ReadEntity(context.Background()) {
		require.NoError(t, err)
		gotEntities = append(gotEntities, entity)
	}

	// read the tokens from the reader
	for token, err := reader.ReadToken(context.Background()); !errors.Is(err, io.EOF); token, err = reader.ReadToken(context.Background()) {
		require.NoError(t, err)
		gotTokens = append(gotTokens, token)
	}
	require.Len(t, gotEntities, 3)
	require.Len(t, gotTokens, 3)

	// verify that the entities and tokens we got from the reader are correct
	// we can't use require.Equals() here because there are protobuf differences in unexported fields
	for i := 0; i < 3; i++ {
		require.True(t, proto.Equal(gotEntities[i], entities[i]))
		require.True(t, proto.Equal(gotTokens[i], tokens[i]))
	}
}

// Test_ActivityLog_ComputeMaxSegmentsAndCapacity verifies the computed max values for
// ActivitySegmentClientCapacity which determines the maximum number of client records per segment and
// activityLogMaxSegmentPerMonth which determines the maximum number of segments per month
func Test_ActivityLog_ComputeMaxSegmentsAndCapacity(t *testing.T) {
	entityRecordInstance := &activity.EntityRecord{}

	// Get the message's descriptor
	descriptor := entityRecordInstance.ProtoReflect().Descriptor()

	// Get the number of fields from the descriptor
	expectedFieldCount := descriptor.Fields().Len()

	// sample record with max values for each field in entity record
	maxSampleRecord := &activity.EntityRecord{
		ClientID:      "11111111-1111-1111-1111-111111111111",
		NamespaceID:   "root",
		Timestamp:     time.Now().Unix(),
		NonEntity:     true,
		MountAccessor: "auth_userpass_00000005",
		ClientType:    "non-entity-token",
		UsageTime:     time.Now().Unix(),
	}
	fieldCountMaxSampleRecord := getNumberofPopulatedFieldsInRecord(maxSampleRecord.ProtoReflect())

	// verify if the maxSampleRecord has populated values for every field in entityRecord
	// this will be used to compute the max client record size to store in storage
	// if this fails, please update the maxSampleRecord with updated entity Record field values
	require.Equal(t, expectedFieldCount, fieldCountMaxSampleRecord)

	// sample record size in bytes
	sampleRecordSize := proto.Size(maxSampleRecord)

	// adding 20 extra bytes to the sample record to account for any extra unknown size increases
	sampleRecordSize = sampleRecordSize + 20

	// records undergo JSON marshalling which increases the size by approx 4/3 times
	sampleRecordSizeStorage := int(float64(sampleRecordSize*4) / float64(3))

	// storage limit per storage entry 512KB
	storageLimitPerEntry := 512 * 1000

	// number of client records that can be stored in a segment
	clientRecordsPerSegment := storageLimitPerEntry / sampleRecordSizeStorage

	require.Condition(t, func() bool {
		return clientRecordsPerSegment <= ActivitySegmentClientCapacity
	}, "client records in segment is greater than expected ActivitySegmentClientCapacity. Please recompute and update ActivitySegmentClientCapacity")

	// max entity records per month
	expectedClientRecordsPerMonth := 700 * 1000

	maxSegmentsPerMonth := expectedClientRecordsPerMonth / clientRecordsPerSegment

	require.Condition(t, func() bool {
		return maxSegmentsPerMonth <= activityLogMaxSegmentPerMonth
	}, "segments per month is greater than expected activityLogMaxSegmentPerMonth. Please recompute and update activityLogMaxSegmentPerMonth")
}

func getNumberofPopulatedFieldsInRecord(msg protoreflect.Message) int {
	count := 0
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		count++
		return true
	})
	return count
}
