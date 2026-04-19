package config

import (
	"fmt"
	"reflect"
	"strings"
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
		if ft.Kind() == reflect.Struct {
			if err := flatten(path, fv, out); err != nil {
				return err
			}
			continue
		}
		out[path] = fv.Interface()
	}
	return nil
}
