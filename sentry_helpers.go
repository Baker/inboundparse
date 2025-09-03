package main

import (
	"github.com/getsentry/sentry-go"
)

// reportToSentry safely reports an error to Sentry if it's initialized
func reportToSentry(err error) {
	if sentry.CurrentHub().Client() != nil {
		sentry.CaptureException(err)
	}
}
