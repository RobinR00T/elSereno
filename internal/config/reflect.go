package config

import (
	"encoding"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// collectTagPaths walks a struct (by value) and returns the set of
// dotted paths that a YAML loader is allowed to set. Only fields with a
// `koanf` struct tag are considered.
func collectTagPaths(prefix string, v any) map[string]struct{} {
	out := make(map[string]struct{})
	walkTagPaths(prefix, reflect.ValueOf(v), out)
	return out
}

func walkTagPaths(prefix string, rv reflect.Value, out map[string]struct{}) {
	if !rv.IsValid() {
		return
	}
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return
	}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("koanf")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.SplitN(tag, ",", 2)[0]
		if name == "" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		out[path] = struct{}{}

		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			walkTagPaths(path, rv.Field(i), out)
		}
	}
}

// structToMap flattens a struct into a koanf-compatible dotted map
// keyed by `koanf` struct tags.
func structToMap(v any) (map[string]any, error) {
	out := make(map[string]any)
	if err := flatten("", reflect.ValueOf(v), out); err != nil {
		return nil, err
	}
	return out, nil
}

func flatten(prefix string, rv reflect.Value, out map[string]any) error {
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("structToMap: expected struct at %q, got %s", prefix, rv.Kind())
	}
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("koanf")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.SplitN(tag, ",", 2)[0]
		if name == "" {
			continue
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		fv := rv.Field(i)
		ft := fv.Type()
		for ft.Kind() == reflect.Pointer {
			if fv.IsNil() {
				break
			}
			fv = fv.Elem()
			ft = fv.Type()
		}
		if ft.Kind() == reflect.Struct && !ft.Implements(textMarshaler) {
			if err := flatten(path, fv, out); err != nil {
				return err
			}
			continue
		}
		out[path] = yamlNative(fv)
	}
	return nil
}

// textMarshaler is the type of encoding.TextMarshaler.
var textMarshaler = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()

// yamlNative returns a default in the type the YAML parser gives the
// same key in a file: the loader merges with StrictMerge, which refuses
// a key whose type differs between defaults and file. Until 2026-10-17
// defaults kept their Go types, so a file with any duration ("30s"
// against time.Duration) or list failed to load with "incorrect types",
// and so did the output of `config show` (PITF-096). The decoder then
// turns the strings back into durations and named types.
func yamlNative(v reflect.Value) any {
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil() {
		return nil
	}
	if d, ok := v.Interface().(time.Duration); ok {
		return d.String()
	}
	// A type that writes itself as text is read back from text.
	if tm, ok := v.Interface().(encoding.TextMarshaler); ok {
		if b, err := tm.MarshalText(); err == nil {
			return string(b)
		}
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return yamlNative(v.Elem())
	case reflect.String:
		return v.String()
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(v.Uint()) // #nosec G115 -- config defaults are small
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.Slice, reflect.Array:
		out := make([]any, v.Len())
		for i := range out {
			out[i] = yamlNative(v.Index(i))
		}
		return out
	default:
		return v.Interface()
	}
}
