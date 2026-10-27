package warpcli

import (
	"context"
	"fmt"
	"time"

	"github.com/Whiteknight07/meshscale/internal/meshaddr"
)

type Progress struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

// EnrollmentError contains only public, actionable text, safe for the app.
type EnrollmentError struct{ State, Message string }

func (e *EnrollmentError) Error() string { return e.Message }
func EnrollmentFailure(state string) error {
	message := map[string]string{
		"not_installed":        "Install Cloudflare One: " + DownloadURL,
		"consumer":             "This Mac has a personal Cloudflare registration. Choose Clear personal registration and connect, or run meshscale up --replace-consumer. This removes the personal registration before team sign-in.",
		"different_org":        "This Mac is registered to another organization. Disconnect Cloudflare and leave that organization in the Cloudflare app before retrying.",
		"registration_error":   "Cannot read Cloudflare registration. Open Cloudflare One and check that its service is running.",
		"setup_failed":         "Device enrollment setup could not be verified. Run meshscale setup --devices in Terminal to review the required account settings.",
		"registration_pending": "Finish signing in in your browser, then choose Connect to retry.",
		"safety_blocked":       "Connection blocked: Cloudflare must be registered to your team and use the meshscale Include profile with " + meshaddr.IPv4Range.String() + ". Check the Cloudflare device profile, then retry.",
		"connection_failed":    "Cloudflare did not connect. Turn off the Cloudflare connection, then try again.",
	}[state]
	if message == "" {
		message = "Cloudflare enrollment could not finish. Turn off the Cloudflare connection and retry."
	}
	return &EnrollmentError{State: state, Message: message}
}

type EnrollmentOptions struct {
	Team            string
	ReplaceConsumer bool
	Pending         bool
	Poll            time.Duration
	Prepare         func(context.Context) error
	Begin           func(context.Context) error
	SetPending      func(bool) error
	Notify          func(Progress)
}

// EnrollMac never uses connector tokens. Registration completes asynchronously
// through the Cloudflare app's URL handler; successful CLI exit is not enrollment.
func (c *Client) EnrollMac(ctx context.Context, options EnrollmentOptions) (err error) {
	if options.Team == "" {
		return fmt.Errorf("a Zero Trust team is required")
	}
	c.Organization, c.RequireSafeProfile = options.Team, true
	if options.Poll <= 0 {
		options.Poll = time.Second
	}
	notify := func(state, message string) {
		if options.Notify != nil {
			options.Notify(Progress{State: state, Message: message})
		}
	}
	info, regErr := c.Registration(ctx)
	if regErr != nil && !IsUnregistered(regErr) {
		return EnrollmentFailure("registration_error")
	}
	if regErr == nil {
		switch {
		case info.AccountType == "Team" && info.Organization != options.Team:
			return EnrollmentFailure("different_org")
		case info.AccountType != "Team":
			if info.AccountType != "Free" && info.AccountType != "Unlimited" {
				return EnrollmentFailure("registration_error")
			}
			if !options.ReplaceConsumer {
				return EnrollmentFailure("consumer")
			}
		}
	}
	if regErr != nil || info.AccountType != "Team" {
		notify("preparing", "Preparing device enrollment")
		if options.Prepare != nil {
			if err := options.Prepare(ctx); err != nil {
				return EnrollmentFailure("setup_failed")
			}
		}
		if regErr == nil {
			if err := c.Disconnect(ctx); err != nil {
				return err
			}
			if err := c.RegistrationDelete(ctx); err != nil {
				return err
			}
			options.Pending = false
		}
		if !options.Pending {
			if options.SetPending != nil {
				if err := options.SetPending(true); err != nil {
					return err
				}
			}
			if options.Begin == nil {
				return fmt.Errorf("enrollment login route is unavailable")
			}
			if err := options.Begin(ctx); err != nil {
				if options.SetPending != nil {
					_ = options.SetPending(false)
				}
				return err
			}
		}
		notify("registration_pending", "Finish signing in in your browser")
		for {
			if err := enrollmentWait(ctx, options.Poll); err != nil {
				return EnrollmentFailure("registration_pending")
			}
			info, regErr = c.Registration(ctx)
			if regErr != nil {
				if IsUnregistered(regErr) {
					continue
				}
				return EnrollmentFailure("registration_error")
			}
			if info.AccountType == "Team" {
				if info.Organization != options.Team {
					return EnrollmentFailure("different_org")
				}
				break
			}
			// Do not delete a personal registration created while login is pending.
			return EnrollmentFailure("consumer")
		}
	}
	if options.SetPending != nil {
		if err := options.SetPending(false); err != nil {
			return err
		}
	}
	notify("checking_safety", "Checking safety settings")
	// Give an asynchronously delivered team profile time to arrive.
	safetyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err := c.CheckSafety(safetyCtx); err == nil {
			break
		}
		if err := enrollmentWait(safetyCtx, options.Poll); err != nil {
			return EnrollmentFailure("safety_blocked")
		}
	}
	notify("connecting", "Connecting")
	defer func() {
		if err != nil {
			stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = c.Disconnect(stop)
		}
	}()
	// Re-read both registration and settings immediately before connect. Arm
	// cleanup first: cancellation can race with the daemon accepting connect.
	if err := c.Connect(ctx); err != nil {
		return EnrollmentFailure("safety_blocked")
	}
	for {
		status, statusErr := c.Status(ctx)
		if statusErr != nil {
			return EnrollmentFailure("connection_failed")
		}
		if status.Connected {
			if err := c.CheckSafety(ctx); err != nil {
				return EnrollmentFailure("safety_blocked")
			}
			notify("connected", "Connected")
			return nil
		}
		if err := enrollmentWait(ctx, options.Poll); err != nil {
			return EnrollmentFailure("connection_failed")
		}
	}
}

func enrollmentWait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
