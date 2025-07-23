package core

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
	"time"
)

const timeLayout = "2006-01-02T15:04:05Z"

func FormatTime(timeRef *time.Time) types.String {
	if timeRef == nil {
		return types.StringNull()
	}

	return types.StringValue(timeRef.UTC().Format(timeLayout))
}

func FormatUnixSecondsRFC822(t int64) string {
	tm := time.Unix(t, 0)
	return tm.Format(time.RFC822)
}

func ParseTime(timeRef types.String) *time.Time {
	v := timeRef.ValueString()
	if len(v) == 0 {
		return nil
	}

	t, _ := time.Parse(timeLayout, v)
	return &t
}
