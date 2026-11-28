package lru

import "testing"

func TestEvictsColdestByCost(t *testing.T) {
	c := New[string, int](10)
	c.Add("a", 1, 4)
	c.Add("b", 2, 4)
	if _, ok := c.Get("a"); !ok { // a is now the warm one
		t.Fatal("a missing")
	}
	if n := c.Add("c", 3, 4); n != 1 {
		t.Fatalf("evicted %d, want 1", n)
	}
	if _, ok := c.Peek("b"); ok {
		t.Fatal("b should have been evicted, it was coldest")
	}
	if c.Used() != 8 || c.Len() != 2 {
		t.Fatalf("used=%d len=%d", c.Used(), c.Len())
	}
}

func TestReplaceAdjustsCostAndTooBigIsRefused(t *testing.T) {
	c := New[string, int](10)
	c.Add("a", 1, 4)
	c.Add("a", 2, 6)
	if c.Used() != 6 || c.Len() != 1 {
		t.Fatalf("used=%d len=%d", c.Used(), c.Len())
	}
	c.Add("a", 3, 11) // over the whole budget: the old value goes, nothing is stored
	if c.Len() != 0 || c.Used() != 0 {
		t.Fatalf("used=%d len=%d", c.Used(), c.Len())
	}
	c.Add("x", 1, 1)
	c.Clear()
	if c.Len() != 0 {
		t.Fatal("clear")
	}
}
