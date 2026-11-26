// Package ojson 保序 JSON：改 relay.json 时保持原键顺序，避免整文件重排，便于人工 diff 与脚本共存。
package ojson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Object 保留键的原始顺序。
type Object struct {
	Keys []string
	M    map[string]any
}

func (o *Object) Get(k string) (any, bool) { v, ok := o.M[k]; return v, ok }

func (o *Object) Set(k string, v any) {
	if _, ok := o.M[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.M[k] = v
}

func (o *Object) Str(k string) string {
	if s, ok := o.M[k].(string); ok {
		return s
	}
	return ""
}

func (o *Object) Int(k string) int64 {
	if n, ok := o.M[k].(json.Number); ok {
		i, _ := n.Int64()
		return i
	}
	return 0
}

func NewObject() *Object { return &Object{M: map[string]any{}} }

// Parse 解析任意 JSON，数字保留为 json.Number 以免精度/格式变化。
func Parse(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := parseValue(d)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("JSON 末尾有多余内容")
	}
	return v, nil
}

func parseValue(d *json.Decoder) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			o := NewObject()
			for d.More() {
				kt, err := d.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				v, err := parseValue(d)
				if err != nil {
					return nil, err
				}
				o.Set(k, v)
			}
			_, err := d.Token()
			return o, err
		case '[':
			arr := []any{}
			for d.More() {
				v, err := parseValue(d)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			_, err := d.Token()
			return arr, err
		}
		return nil, fmt.Errorf("意外的分隔符 %v", x)
	default:
		return x, nil
	}
}

// Marshal 以 2 空格缩进输出（与 jq 默认风格一致）。
func Marshal(v any) []byte {
	var b strings.Builder
	write(&b, v, 0)
	b.WriteByte('\n')
	return []byte(b.String())
}

func write(b *strings.Builder, v any, ind int) {
	pad := func(n int) { b.WriteString(strings.Repeat("  ", n)) }
	switch x := v.(type) {
	case *Object:
		if len(x.Keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range x.Keys {
			pad(ind + 1)
			kb, _ := encStr(k)
			b.Write(kb)
			b.WriteString(": ")
			write(b, x.M[k], ind+1)
			if i < len(x.Keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		pad(ind)
		b.WriteByte('}')
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range x {
			pad(ind + 1)
			write(b, e, ind+1)
			if i < len(x)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		pad(ind)
		b.WriteByte(']')
	case string:
		sb, _ := encStr(x)
		b.Write(sb)
	case json.Number:
		b.WriteString(x.String())
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case nil:
		b.WriteString("null")
	default:
		jb, _ := json.Marshal(x)
		b.Write(jb)
	}
}

func encStr(s string) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
