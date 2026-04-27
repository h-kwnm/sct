package main

import (
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
			// tileIndex >= d^3 = 10^9 → returns empty string.
			name:      "tile index out of range returns empty string",
			tileIndex: 1_000_000_000, level: 0, treeSize: 1_000_000_001*256 + 1,
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
			name:      "single-leaf tree",
			m: 0, n: 1,
			wantNodes: []wantNode{},
		},
		{
			name:      "two-leaf tree, leaf 0",
			m: 0, n: 2,
			wantNodes: []wantNode{
				{start: 1, end: 2},
			},
		},
		{
			name:      "two-leaf tree, leaf 1",
			m: 1, n: 2,
			wantNodes: []wantNode{
				{start: 0, end: 1},
			},
		},
		{
			name:      "power-of-2 tree (n=8), leaf 0",
			m: 0, n: 8,
			wantNodes: []wantNode{
				{start: 1, end: 2},
				{start: 2, end: 4},
				{start: 4, end: 8},
			},
		},
		{
			name:      "non-full tree (n=27), leaf 10",
			m: 10, n: 27,
			wantNodes: []wantNode{
				{start: 11, end: 12},
				{start: 8, end: 10},
				{start: 12, end: 16},
				{start: 0, end: 8},
				{start: 16, end: 27},
			},
		},
		{
			name:      "non-full tree (n=27), leaf 20",
			m: 20, n: 27,
			wantNodes: []wantNode{
				{start: 21, end: 22},
				{start: 22, end: 24},
				{start: 16, end: 20},
				{start: 24, end: 27},
				{start: 0, end: 16},
			},
		},
		{
			name:      "cross-tile tree (n=257), last leaf",
			m: 256, n: 257,
			wantNodes: []wantNode{
				{start: 0, end: 256},
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
