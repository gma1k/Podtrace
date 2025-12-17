package cri

import (
	"strings"
)

func findJSONString(obj any, keyPaths []string) (string, bool) {
	for _, kp := range keyPaths {
		if v, ok := findJSONValue(obj, strings.Split(kp, ".")); ok {
			if s, ok := v.(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

func findJSONInt(obj any, keys []string) (int64, bool) {
	for _, k := range keys {
		if v, ok := findJSONValue(obj, strings.Split(k, ".")); ok {
			switch t := v.(type) {
			case float64:
				return int64(t), true
			case int64:
				return t, true
			case int:
				return int64(t), true
			}
		}
	}
	return 0, false
}

func findJSONValue(obj any, path []string) (any, bool) {
	if len(path) == 0 {
		return obj, true
	}
	cur := obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := m[p]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}
