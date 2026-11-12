package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"
)

const MaxDepth = 32

const MaxSafeInteger int64 = 1<<53 - 1

type Kind int

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

func (k Kind) String() string {
	switch k {
	case Null:
		return "null"
	case Bool:
		return "boolean"
	case Number:
		return "number"
	case String:
		return "string"
	case Array:
		return "array"
	case Object:
		return "object"
	}
	return "unknown"
}

type Value struct {
	Kind Kind
	Bool bool
	Num  string
	Str  string
	Arr  []Value
	Obj  *Obj
}

type Obj struct {
	Keys   []string
	Fields map[string]Value
}

var integerLiteral = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func Parse(data []byte) (Value, error) {
	if !utf8.Valid(data) {
		return Value{}, errors.New("input is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return Value{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return Value{}, errors.New("unexpected data after the top-level JSON value")
	}
	return v, nil
}

func ParseObject(data []byte) (*Obj, error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if v.Kind != Object {
		return nil, fmt.Errorf("top-level value must be an object, got %s", v.Kind)
	}
	return v.Obj, nil
}

func parseValue(dec *json.Decoder, depth int) (Value, error) {
	if depth > MaxDepth {
		return Value{}, errors.New("JSON nesting too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return Value{}, invalid(err)
	}
	switch t := tok.(type) {
	case nil:
		return Value{Kind: Null}, nil
	case bool:
		return Value{Kind: Bool, Bool: t}, nil
	case json.Number:
		return Value{Kind: Number, Num: t.String()}, nil
	case string:
		return Value{Kind: String, Str: t}, nil
	case json.Delim:
		switch t {
		case '{':
			o := &Obj{Fields: map[string]Value{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return Value{}, invalid(err)
				}
				key, ok := kt.(string)
				if !ok {
					return Value{}, errors.New("invalid JSON: object key is not a string")
				}
				if _, dup := o.Fields[key]; dup {
					return Value{}, fmt.Errorf("duplicate field %q", key)
				}
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return Value{}, err
				}
				o.Keys = append(o.Keys, key)
				o.Fields[key] = v
			}
			if _, err := dec.Token(); err != nil {
				return Value{}, invalid(err)
			}
			return Value{Kind: Object, Obj: o}, nil
		case '[':
			arr := []Value{}
			for dec.More() {
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return Value{}, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil {
				return Value{}, invalid(err)
			}
			return Value{Kind: Array, Arr: arr}, nil
		}
	}
	return Value{}, fmt.Errorf("invalid JSON: unexpected token %v", tok)
}

func invalid(err error) error {
	if err == io.EOF {
		return errors.New("invalid JSON: unexpected end of input")
	}
	return fmt.Errorf("invalid JSON: %v", err)
}

func (o *Obj) ExpectFields(where string, keys ...string) error {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
		if _, ok := o.Fields[k]; !ok {
			return fmt.Errorf("%s: missing field %q", where, k)
		}
	}
	for _, k := range o.Keys {
		if !want[k] {
			return fmt.Errorf("%s: unexpected field %q", where, k)
		}
	}
	return nil
}

func (o *Obj) get(key string, kind Kind) (Value, error) {
	v, ok := o.Fields[key]
	if !ok {
		return Value{}, fmt.Errorf("missing field %q", key)
	}
	if v.Kind != kind {
		return Value{}, fmt.Errorf("field %q must be a %s, got %s", key, kind, v.Kind)
	}
	return v, nil
}

func (o *Obj) String(key string) (string, error) {
	v, err := o.get(key, String)
	return v.Str, err
}

func (o *Obj) Object(key string) (*Obj, error) {
	v, err := o.get(key, Object)
	return v.Obj, err
}

func (o *Obj) Array(key string) ([]Value, error) {
	v, err := o.get(key, Array)
	return v.Arr, err
}

func (o *Obj) Integer(key string) (int64, error) {
	v, err := o.get(key, Number)
	if err != nil {
		return 0, err
	}
	if !integerLiteral.MatchString(v.Num) {
		return 0, fmt.Errorf("field %q must be a non-negative integer without leading zeros, got %s", key, v.Num)
	}
	n, err := strconv.ParseInt(v.Num, 10, 64)
	if err != nil || n > MaxSafeInteger {
		return 0, fmt.Errorf("field %q is out of range 0..%d", key, MaxSafeInteger)
	}
	return n, nil
}
