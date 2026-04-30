package main

import (
	"crypto/sha256"
	"encoding/base64"
	"math/bits"
	"testing"
)

// --- buildTileIndex ---

func TestBuildTileIndex(t *testing.T) {
	tests := []struct {
		name      string
		tileIndex uint64
		level     int
		treeSize  uint64
		want      string
	}{
		{
			// Tile 0 of 2: not the max tile, so no .p suffix.
			name:      "full tile, not max",
			tileIndex: 0, level: 0, treeSize: 512,
			want: "tile/0/000",
		},
		{
			// Only tile, and treeSize%256==0, so partialIndex wraps to 0 → no suffix.
			name:      "max tile that is exactly full (no .p suffix)",
			tileIndex: 0, level: 0, treeSize: 256,
			want: "tile/0/000",
		},
		{
			// 3 of 256 slots used.
			name:      "partial tile, 3 entries",
			tileIndex: 0, level: 0, treeSize: 3,
			want: "tile/0/000.p/3",
		},
		{
			// All 27 leaves fit in one level-0 tile with 256 slots.
			name:      "level-0 partial tile for tree size 27",
			tileIndex: 0, level: 0, treeSize: 27,
			want: "tile/0/000.p/27",
		},
		{
			// Level-1 tile covers 256*256=65536 records. For n=257: 1 level-1 entry
			// (entry 0 = MTH([0,256))). The incomplete subtree [256,257) is not stored at level 1.
			name:      "level-1 partial tile for tree size 257",
			tileIndex: 0, level: 1, treeSize: 257,
			want: "tile/1/000.p/1",
		},
		{
			// tileIndex=1000 triggers the x-prefix format (d=1000).
			name:      "tile index at start of x-prefix range",
			tileIndex: 1000, level: 0, treeSize: 1001*256 + 1, // not max tile
			want: "tile/0/x001/000",
		},
		{
			// tileIndex=1000000 triggers the double x-prefix format.
			name:      "tile index in double x-prefix range",
			tileIndex: 1000000, level: 0, treeSize: 1000001*256 + 1, // not max tile
			want: "tile/0/x001/x000/000",
		},
		{
			// tileIndex=10^9 triggers the triple x-prefix format.
			name:      "tile index out of range returns empty string",
			tileIndex: 1_000_000_000, level: 0, treeSize: 1_000_000_001*256 + 1,
			want: "tile/0/x001/x000/x000/000",
		},
		{
			// tileIndex >= 2^40 -> returns empty string.
			name:      "tile index out of range returns empty string",
			tileIndex: (1 << 40) + 1, level: 0, treeSize: (1 << 40) + 2,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTileIndex(tt.tileIndex, tt.level, tt.treeSize)
			if got != tt.want {
				t.Errorf("buildTileIndex(%d, %d, %d) = %q, want %q",
					tt.tileIndex, tt.level, tt.treeSize, got, tt.want)
			}
		})
	}
}

// --- verifyInclusion ---

// testLeaves returns n deterministic leaf hashes using sha256([]byte{i}).
func testLeaves(n int) [][32]byte {
	hashes := make([][32]byte, n)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}
	return hashes
}

// testMTH computes the Merkle tree root of a list of leaf hashes following
// RFC 6962: split at the largest power of 2 less than n.
func testMTH(hashes [][32]byte) [32]byte {
	if len(hashes) == 1 {
		return hashes[0]
	}
	k := 1 << (bits.Len(uint(len(hashes)-1)) - 1)
	return merkleHash(testMTH(hashes[:k]), testMTH(hashes[k:]))
}

// testCheckpoint builds a Checkpoint whose root matches the given leaf hashes.
func testCheckpoint(leaves [][32]byte) Checkpoint {
	root := testMTH(leaves)
	return Checkpoint{
		Origin:   "test.example.com/log",
		TreeSize: uint64(len(leaves)),
		RootHash: base64.StdEncoding.EncodeToString(root[:]),
	}
}

// testTiles builds the tiles map for a single-tile tree (n ≤ 256).
func testTiles(leaves [][32]byte, n uint64) map[string]Tile {
	return map[string]Tile{
		buildTileIndex(0, 0, n): {Hashes: leaves},
	}
}

func TestVerifyInclusion(t *testing.T) {
	verify := func(t *testing.T, m uint64, leaves [][32]byte, tiles map[string]Tile) bool {
		t.Helper()
		ap := getAuditPath(m, uint64(len(leaves)))
		res, err := verifyInclusion(ap, tiles, buildTileAccesses(ap), testCheckpoint(leaves))
		if err != nil {
			t.Fatalf("verifyInclusion error: %v", err)
		}
		return res.VerificationSuccess
	}

	// Single tile cases (n ≤ 256): leaf hashes all fit in tile/0/000[.p/n].
	t.Run("single leaf n=1", func(t *testing.T) {
		leaves := testLeaves(1)
		if !verify(t, 0, leaves, testTiles(leaves, 1)) {
			t.Error("want true")
		}
	})

	for _, tc := range []struct {
		name string
		n    int
		m    uint64
	}{
		// power-of-2 sizes
		{"n=2 m=0", 2, 0},
		{"n=2 m=1", 2, 1},
		{"n=4 m=0", 4, 0},
		{"n=4 m=1", 4, 1},
		{"n=4 m=2", 4, 2},
		{"n=4 m=3", 4, 3},
		// non-power-of-2: right-branch sibling is a non-complete subtree
		{"n=3 m=0", 3, 0},
		{"n=3 m=1", 3, 1},
		{"n=3 m=2", 3, 2},
		{"n=5 m=4", 5, 4},
		{"n=7 m=0", 7, 0},
		{"n=7 m=3", 7, 3},
		{"n=7 m=6", 7, 6},
		// larger non-power-of-2
		{"n=100 m=0", 100, 0},
		{"n=100 m=49", 100, 49},
		{"n=100 m=99", 100, 99},
		// just below tile boundary
		{"n=255 m=0", 255, 0},
		{"n=255 m=127", 255, 127},
		{"n=255 m=254", 255, 254},
		// exactly one full tile: no .p suffix on tile path
		{"n=256 m=0", 256, 0},
		{"n=256 m=128", 256, 128},
		{"n=256 m=255", 256, 255},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaves := testLeaves(tc.n)
			if !verify(t, tc.m, leaves, testTiles(leaves, uint64(tc.n))) {
				t.Error("want true")
			}
		})
	}

	// Cross-tile: n=257 forces a level-1 tile for the sibling [0,256).
	t.Run("cross-tile n=257 m=256", func(t *testing.T) {
		leaves := testLeaves(257)
		const n = uint64(257)
		tiles := map[string]Tile{
			buildTileIndex(0, 0, n): {Hashes: leaves[0:256]},
			buildTileIndex(1, 0, n): {Hashes: leaves[256:257]},
			buildTileIndex(0, 1, n): {Hashes: [][32]byte{computeMth(leaves[0:256])}},
		}
		if !verify(t, 256, leaves, tiles) {
			t.Error("want true")
		}
	})

	// Failure: root hash does not match.
	t.Run("wrong root returns false", func(t *testing.T) {
		leaves := testLeaves(7)
		wrong := sha256.Sum256([]byte("wrong"))
		cp := Checkpoint{
			Origin:   "test.example.com/log",
			TreeSize: 7,
			RootHash: base64.StdEncoding.EncodeToString(wrong[:]),
		}
		ap := getAuditPath(3, 7)
		res, err := verifyInclusion(ap, testTiles(leaves, 7), buildTileAccesses(ap), cp)
		if err != nil {
			t.Fatalf("verifyInclusion error: %v", err)
		}
		if res.VerificationSuccess {
			t.Error("want false")
		}
	})

	// Failure: the leaf being verified has been tampered.
	t.Run("tampered verified leaf returns false", func(t *testing.T) {
		leaves := testLeaves(7)
		tampered := make([][32]byte, len(leaves))
		copy(tampered, leaves)
		tampered[3] = sha256.Sum256([]byte("tampered"))
		ap := getAuditPath(3, 7)
		// checkpoint root is from original leaves; tile contains the tampered hash
		res, err := verifyInclusion(ap, testTiles(tampered, 7), buildTileAccesses(ap), testCheckpoint(leaves))
		if err != nil {
			t.Fatalf("verifyInclusion error: %v", err)
		}
		if res.VerificationSuccess {
			t.Error("want false")
		}
	})

	// Failure: a sibling tile entry has been tampered (leaf being verified is untouched).
	t.Run("tampered sibling returns false", func(t *testing.T) {
		leaves := testLeaves(7)
		tampered := make([][32]byte, len(leaves))
		copy(tampered, leaves)
		tampered[0] = sha256.Sum256([]byte("tampered")) // sibling of leaf 3
		// checkpoint root is computed from untampered leaves
		ap := getAuditPath(3, 7)
		res, err := verifyInclusion(ap, testTiles(tampered, 7), buildTileAccesses(ap), testCheckpoint(leaves))
		if err != nil {
			t.Fatalf("verifyInclusion error: %v", err)
		}
		if res.VerificationSuccess {
			t.Error("want false")
		}
	})
}

// --- getAuditPath ---

func TestGetAuditPathInvalid(t *testing.T) {
	tests := []struct {
		name string
		m, n uint64
	}{
		{"m equals n", 5, 5},
		{"m greater than n", 10, 5},
		{"n is zero", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := getAuditPath(tt.m, tt.n)
			if path.TreeSize != 0 || len(path.Nodes) != 0 {
				t.Errorf("expected empty AuditPath, got %+v", path)
			}
		})
	}
}

func TestGetAuditPath(t *testing.T) {
	type wantNode struct {
		start, end uint64
	}

	tests := []struct {
		name      string
		m, n      uint64
		wantNodes []wantNode
	}{
		{
			name: "single-leaf tree",
			m:    0, n: 1,
			wantNodes: []wantNode{},
		},
		{
			name: "two-leaf tree, leaf 0",
			m:    0, n: 2,
			wantNodes: []wantNode{
				{start: 1, end: 2},
			},
		},
		{
			name: "two-leaf tree, leaf 1",
			m:    1, n: 2,
			wantNodes: []wantNode{
				{start: 0, end: 1},
			},
		},
		{
			name: "power-of-2 tree (n=8), leaf 0",
			m:    0, n: 8,
			wantNodes: []wantNode{
				{start: 1, end: 2},
				{start: 2, end: 4},
				{start: 4, end: 8},
			},
		},
		{
			name: "non-full tree (n=27), leaf 10",
			m:    10, n: 27,
			wantNodes: []wantNode{
				{start: 11, end: 12},
				{start: 8, end: 10},
				{start: 12, end: 16},
				{start: 0, end: 8},
				{start: 16, end: 27},
			},
		},
		{
			name: "non-full tree (n=27), leaf 20",
			m:    20, n: 27,
			wantNodes: []wantNode{
				{start: 21, end: 22},
				{start: 22, end: 24},
				{start: 16, end: 20},
				{start: 24, end: 27},
				{start: 0, end: 16},
			},
		},
		{
			name: "cross-tile tree (n=257), last leaf",
			m:    256, n: 257,
			wantNodes: []wantNode{
				{start: 0, end: 256},
			},
		},
		{
			name: "maximum size tree (n=2^40), last leaf",
			m:    (1 << 40) - 1, n: 1 << 40,
			wantNodes: []wantNode{
				{start: 1099511627774, end: 1099511627775},
				{start: 1099511627772, end: 1099511627774},
				{start: 1099511627768, end: 1099511627772},
				{start: 1099511627760, end: 1099511627768},
				{start: 1099511627744, end: 1099511627760},
				{start: 1099511627712, end: 1099511627744},
				{start: 1099511627648, end: 1099511627712},
				{start: 1099511627520, end: 1099511627648},
				{start: 1099511627264, end: 1099511627520},
				{start: 1099511626752, end: 1099511627264},
				{start: 1099511625728, end: 1099511626752},
				{start: 1099511623680, end: 1099511625728},
				{start: 1099511619584, end: 1099511623680},
				{start: 1099511611392, end: 1099511619584},
				{start: 1099511595008, end: 1099511611392},
				{start: 1099511562240, end: 1099511595008},
				{start: 1099511496704, end: 1099511562240},
				{start: 1099511365632, end: 1099511496704},
				{start: 1099511103488, end: 1099511365632},
				{start: 1099510579200, end: 1099511103488},
				{start: 1099509530624, end: 1099510579200},
				{start: 1099507433472, end: 1099509530624},
				{start: 1099503239168, end: 1099507433472},
				{start: 1099494850560, end: 1099503239168},
				{start: 1099478073344, end: 1099494850560},
				{start: 1099444518912, end: 1099478073344},
				{start: 1099377410048, end: 1099444518912},
				{start: 1099243192320, end: 1099377410048},
				{start: 1098974756864, end: 1099243192320},
				{start: 1098437885952, end: 1098974756864},
				{start: 1097364144128, end: 1098437885952},
				{start: 1095216660480, end: 1097364144128},
				{start: 1090921693184, end: 1095216660480},
				{start: 1082331758592, end: 1090921693184},
				{start: 1065151889408, end: 1082331758592},
				{start: 1030792151040, end: 1065151889408},
				{start: 962072674304, end: 1030792151040},
				{start: 824633720832, end: 962072674304},
				{start: 549755813888, end: 824633720832},
				{start: 0, end: 549755813888},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := getAuditPath(tt.m, tt.n)

			if path.LeafIndex != tt.m {
				t.Errorf("LeafIndex = %d, want %d", path.LeafIndex, tt.m)
			}
			if path.TreeSize != tt.n {
				t.Errorf("TreeSize = %d, want %d", path.TreeSize, tt.n)
			}
			if len(path.Nodes) != len(tt.wantNodes) {
				t.Fatalf("len(Nodes) = %d, want %d", len(path.Nodes), len(tt.wantNodes))
			}

			for i, wn := range tt.wantNodes {
				n := path.Nodes[i]
				if n.Start != wn.start {
					t.Errorf("nodes[%d].Start = %d, want %d", i, n.Start, wn.start)
				}
				if n.End != wn.end {
					t.Errorf("nodes[%d].End = %d, want %d", i, n.End, wn.end)
				}
			}
		})
	}
}

func TestGetAuditTile(t *testing.T) {
	tests := []struct {
		name      string
		m, n      uint64
		wantTiles map[string][]IndexRange
	}{
		{
			name: "single tile",
			m:    1, n: 16,
			wantTiles: map[string][]IndexRange{
				"tile/0/000.p/16": {
					IndexRange{Offset: 1, Count: 1},
					IndexRange{Offset: 0, Count: 1},
					IndexRange{Offset: 2, Count: 2},
					IndexRange{Offset: 4, Count: 4},
					IndexRange{Offset: 8, Count: 8},
				},
			},
		},
		{
			name: "two tiles",
			m:    1, n: 257,
			wantTiles: map[string][]IndexRange{
				"tile/0/000": {
					IndexRange{Offset: 1, Count: 1},
					IndexRange{Offset: 0, Count: 1},
					IndexRange{Offset: 2, Count: 2},
					IndexRange{Offset: 4, Count: 4},
					IndexRange{Offset: 8, Count: 8},
					IndexRange{Offset: 16, Count: 16},
					IndexRange{Offset: 32, Count: 32},
					IndexRange{Offset: 64, Count: 64},
					IndexRange{Offset: 128, Count: 128},
				},
				"tile/0/001.p/1": {
					IndexRange{Offset: 0, Count: 1},
				},
			},
		},
		{
			name: "two tiles, last leaf",
			m:    257, n: 258,
			wantTiles: map[string][]IndexRange{
				"tile/0/001.p/2": {
					IndexRange{Offset: 1, Count: 1},
					IndexRange{Offset: 0, Count: 1},
				},
				"tile/1/000.p/1": {
					IndexRange{Offset: 0, Count: 1},
				},
			},
		},
		{
			name: "leaf 1 in 2^40 tree",
			m:    1, n: 1 << 40,
			wantTiles: map[string][]IndexRange{
				"tile/0/000": {
					{Offset: 1, Count: 1}, {Offset: 0, Count: 1},
					{Offset: 2, Count: 2}, {Offset: 4, Count: 4},
					{Offset: 8, Count: 8}, {Offset: 16, Count: 16},
					{Offset: 32, Count: 32}, {Offset: 64, Count: 64},
					{Offset: 128, Count: 128},
				},
				"tile/1/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
				"tile/2/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
				"tile/3/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
				"tile/4/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
			},
		},
		{
			name: "last leaf in 2^40 tree",
			m:    (1 << 40) - 1, n: 1 << 40,
			wantTiles: map[string][]IndexRange{
				"tile/0/x004/x294/x967/295": {
					{Offset: 255, Count: 1}, {Offset: 254, Count: 1},
					{Offset: 252, Count: 2}, {Offset: 248, Count: 4},
					{Offset: 240, Count: 8}, {Offset: 224, Count: 16},
					{Offset: 192, Count: 32}, {Offset: 128, Count: 64},
					{Offset: 0, Count: 128},
				},
				"tile/1/x016/x777/215": {
					{Offset: 254, Count: 1}, {Offset: 252, Count: 2},
					{Offset: 248, Count: 4}, {Offset: 240, Count: 8},
					{Offset: 224, Count: 16}, {Offset: 192, Count: 32},
					{Offset: 128, Count: 64}, {Offset: 0, Count: 128},
				},
				"tile/2/x065/535": {
					{Offset: 254, Count: 1}, {Offset: 252, Count: 2},
					{Offset: 248, Count: 4}, {Offset: 240, Count: 8},
					{Offset: 224, Count: 16}, {Offset: 192, Count: 32},
					{Offset: 128, Count: 64}, {Offset: 0, Count: 128},
				},
				"tile/3/255": {
					{Offset: 254, Count: 1}, {Offset: 252, Count: 2},
					{Offset: 248, Count: 4}, {Offset: 240, Count: 8},
					{Offset: 224, Count: 16}, {Offset: 192, Count: 32},
					{Offset: 128, Count: 64}, {Offset: 0, Count: 128},
				},
				"tile/4/000": {
					{Offset: 254, Count: 1}, {Offset: 252, Count: 2},
					{Offset: 248, Count: 4}, {Offset: 240, Count: 8},
					{Offset: 224, Count: 16}, {Offset: 192, Count: 32},
					{Offset: 128, Count: 64}, {Offset: 0, Count: 128},
				},
			},
		},
		{
			name: "last leaf in 2^32+1 tree",
			m:    1 << 32, n: (1 << 32) + 1,
			wantTiles: map[string][]IndexRange{
				"tile/0/x016/x777/216.p/1": {{Offset: 0, Count: 1}},
				"tile/4/000.p/1":           {{Offset: 0, Count: 1}},
			},
		},
		{
			name: "leaf 1 in 2^32+1 tree",
			m:    1, n: (1 << 32) + 1,
			wantTiles: map[string][]IndexRange{
				"tile/0/000": {
					{Offset: 1, Count: 1}, {Offset: 0, Count: 1},
					{Offset: 2, Count: 2}, {Offset: 4, Count: 4},
					{Offset: 8, Count: 8}, {Offset: 16, Count: 16},
					{Offset: 32, Count: 32}, {Offset: 64, Count: 64},
					{Offset: 128, Count: 128},
				},
				"tile/0/x016/x777/216.p/1": {{Offset: 0, Count: 1}},
				"tile/1/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
				"tile/2/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
				"tile/3/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
			},
		},
		{
			name: "last leaf in 2^24+1 tree",
			m:    1 << 24, n: (1 << 24) + 1,
			wantTiles: map[string][]IndexRange{
				"tile/0/x065/536.p/1": {{Offset: 0, Count: 1}},
				"tile/3/000.p/1":      {{Offset: 0, Count: 1}},
			},
		},
		{
			name: "leaf 1 in 2^24+1 tree",
			m:    1, n: (1 << 24) + 1,
			wantTiles: map[string][]IndexRange{
				"tile/0/000": {
					{Offset: 1, Count: 1}, {Offset: 0, Count: 1},
					{Offset: 2, Count: 2}, {Offset: 4, Count: 4},
					{Offset: 8, Count: 8}, {Offset: 16, Count: 16},
					{Offset: 32, Count: 32}, {Offset: 64, Count: 64},
					{Offset: 128, Count: 128},
				},
				"tile/0/x065/536.p/1": {{Offset: 0, Count: 1}},
				"tile/1/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
				"tile/2/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
			},
		},
		{
			name: "last leaf in 2^16+1 tree",
			m:    1 << 16, n: (1 << 16) + 1,
			wantTiles: map[string][]IndexRange{
				"tile/0/256.p/1": {{Offset: 0, Count: 1}},
				"tile/2/000.p/1": {{Offset: 0, Count: 1}},
			},
		},
		{
			name: "leaf 1 in 2^16+1 tree",
			m:    1, n: (1 << 16) + 1,
			wantTiles: map[string][]IndexRange{
				"tile/0/000": {
					{Offset: 1, Count: 1}, {Offset: 0, Count: 1},
					{Offset: 2, Count: 2}, {Offset: 4, Count: 4},
					{Offset: 8, Count: 8}, {Offset: 16, Count: 16},
					{Offset: 32, Count: 32}, {Offset: 64, Count: 64},
					{Offset: 128, Count: 128},
				},
				"tile/0/256.p/1": {{Offset: 0, Count: 1}},
				"tile/1/000": {
					{Offset: 1, Count: 1}, {Offset: 2, Count: 2},
					{Offset: 4, Count: 4}, {Offset: 8, Count: 8},
					{Offset: 16, Count: 16}, {Offset: 32, Count: 32},
					{Offset: 64, Count: 64}, {Offset: 128, Count: 128},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tiles := getAuditTiles(tt.m, tt.n)

			if tiles.LeafIndex != tt.m {
				t.Errorf("LeafIndex = %d, want %d", tiles.LeafIndex, tt.m)
			}
			if tiles.TreeSize != tt.n {
				t.Errorf("TreeSize = %d, want %d", tiles.TreeSize, tt.n)
			}
			if len(tiles.Tiles) != len(tt.wantTiles) {
				t.Fatalf("len(Tiles) = %d, want %d", len(tiles.Tiles), len(tt.wantTiles))
			}

			for k, wt := range tt.wantTiles {
				if len(tiles.Tiles[k]) != len(wt) {
					t.Fatalf("tile %s: got %d ranges, want %d", k, len(tiles.Tiles[k]), len(wt))
				}
				for i, v := range wt {
					if tiles.Tiles[k][i] != v {
						t.Errorf("tile[%d]=%v, want %v", i, tiles.Tiles[k][i], wt)
					}
				}
			}
		})
	}
}
