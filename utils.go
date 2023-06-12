package main

import (
	"time"

	neucoreapi "github.com/bravecollective/neucore-api-go"
)

func contains[T comparable](needle T, haystack []T) bool {
	for i := range haystack {
		if haystack[i] == needle {
			return true
		}
	}
	return false
}

func min[T ~int](a, b T) T {
	if a <= b {
		return a
	}
	return b
}

func dateMax(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func characterExistsInNeucore(needle int64, haystack []neucoreapi.Character) bool {
	for _, val := range haystack {
		if val.GetId() == needle {
			return true
		}
	}

	return false
}

func characterHasValidNeucoreToken(needle int64, haystack []neucoreapi.Character) bool {
	for _, val := range haystack {
		if val.GetId() == needle {
			return val.GetValidToken()
		}
	}

	// Character missing from neucore.
	return false
}

func playerBelongsToGroup(needle string, haystack []neucoreapi.Group) bool {
	for _, val := range haystack {
		if val.GetName() == needle {
			return true
		}
	}
	return false
}
