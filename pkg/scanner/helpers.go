package scanner

import (
	"encoding/json"
	"fmt"
	"runtime"
)

func marshalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

func platformString() string {
	return fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)
}
