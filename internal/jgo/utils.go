package jgo

func find[T comparable](v T, l []T) bool {
	for _, vv := range l {
		if v == vv {
			return true
		}
	}
	return false
}
