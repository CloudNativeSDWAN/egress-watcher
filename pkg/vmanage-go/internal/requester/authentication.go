package requester

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const authThreshold = 20 * time.Minute

type authenticator struct {
	username string
	password string

	sync.Mutex
	lastAuth time.Time
}

func (a *authenticator) authenticate(ctx context.Context, r *Requester) error {
	a.Lock()
	defer a.Unlock()

	if time.Since(a.lastAuth) <= authThreshold {
		return nil
	}

	defer func() {
		a.lastAuth = time.Now()
	}()

	authReq := r.CloneWithNewBasePath("")
	authReq.tokens.XsrfToken = ""

	sessionID, err := getSessionID(ctx, authReq, a.username, a.password)
	if err != nil {
		return fmt.Errorf("error while trying to get session ID: %w", err)
	}

	xsrfToken, err := getXSRFToken(ctx, authReq)
	if err != nil {
		return fmt.Errorf("error while trying to get xsrf token: %w", err)
	}

	r.tokens.XsrfToken = *xsrfToken
	r.tokens.SessionID = *sessionID

	return nil
}
