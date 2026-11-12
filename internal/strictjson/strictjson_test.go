package strictjson

import (
	"strings"
	"testing"
)

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"duplicate key":          `{"a":1,"a":1}`,
		"duplicate after escape": `{"a":1,"\u0061":2}`,
		"nested duplicate":       `{"x":{"b":true,"b":false}}`,
		"duplicate in array obj": `{"x":[{"k":"1","k":"2"}]}`,
		"trailing object":        `{} {}`,
		"trailing garbage":       `{"a":1}x`,
		"truncated":              `{"a":`,
		"empty":                  ``,
		"only whitespace":        "  \n",
		"invalid utf8":           "{\"a\":\"\xff\"}",
		"single quotes":          `{'a':1}`,
		"trailing comma":         `{"a":1,}`,
		"bare word":              `{"a":nul}`,
		"too deep":               strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2),
		"missing comma":          `{"a":1 "b":2}`,
		"non-string key":         `{1:2}`,
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error for %q", name, in)
		}
	}
}

func TestParseAcceptsAndKeepsOrder(t *testing.T) {
	o, err := ParseObject([]byte(" {\n\t\"b\" : [1, \"x\", null, true, {\"c\":{}}],\r\n \"a\":\"\\u0041\"} \n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(o.Keys, ",") != "b,a" {
		t.Fatalf("keys order: %v", o.Keys)
	}
	if s, _ := o.String("a"); s != "A" {
		t.Fatalf("escape not decoded: %q", s)
	}
	arr, err := o.Array("b")
	if err != nil || len(arr) != 5 || arr[2].Kind != Null || arr[3].Kind != Bool || arr[4].Kind != Object {
		t.Fatalf("array: %+v %v", arr, err)
	}
}

func TestParseObjectRequiresObject(t *testing.T) {
	for _, in := range []string{`[]`, `"x"`, `1`, `null`, `true`} {
		if _, err := ParseObject([]byte(in)); err == nil {
			t.Errorf("expected error for top-level %s", in)
		}
	}
}

func TestExpectFields(t *testing.T) {
	o, _ := ParseObject([]byte(`{"a":1,"b":2}`))
	if err := o.ExpectFields("t", "a", "b"); err != nil {
		t.Fatal(err)
	}
	if err := o.ExpectFields("t", "a"); err == nil || !strings.Contains(err.Error(), `unexpected field "b"`) {
		t.Fatalf("extra field not reported: %v", err)
	}
	if err := o.ExpectFields("t", "a", "b", "c"); err == nil || !strings.Contains(err.Error(), `missing field "c"`) {
		t.Fatalf("missing field not reported: %v", err)
	}
}

func TestTypedGetters(t *testing.T) {
	o, err := ParseObject([]byte(`{"s":"x","n":null,"b":true,"i":42,"z":0,"max":9007199254740991,
		"big":9007199254740992,"neg":-1,"lead":007,"frac":1.0,"exp":1e3,"negz":-0,"str":"5","arr":[],"obj":{}}`))
	if err == nil {
		t.Fatal("leading zero 007 must be invalid JSON")
	}
	o, err = ParseObject([]byte(`{"s":"x","n":null,"b":true,"i":42,"z":0,"max":9007199254740991,
		"big":9007199254740992,"neg":-1,"frac":1.0,"exp":1e3,"negz":-0,"str":"5","arr":[],"obj":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := o.String("s"); err != nil || v != "x" {
		t.Errorf("String(s) = %q, %v", v, err)
	}
	for _, k := range []string{"n", "b", "i", "arr", "obj"} {
		if _, err := o.String(k); err == nil {
			t.Errorf("String(%s) should fail", k)
		}
	}
	for k, want := range map[string]int64{"i": 42, "z": 0, "max": 9007199254740991} {
		if v, err := o.Integer(k); err != nil || v != want {
			t.Errorf("Integer(%s) = %d, %v", k, v, err)
		}
	}
	for _, k := range []string{"big", "neg", "frac", "exp", "negz", "str", "b", "n", "missing"} {
		if _, err := o.Integer(k); err == nil {
			t.Errorf("Integer(%s) should fail", k)
		}
	}
	if _, err := o.Object("arr"); err == nil {
		t.Error("Object(arr) should fail")
	}
	if _, err := o.Array("obj"); err == nil {
		t.Error("Array(obj) should fail")
	}
}
