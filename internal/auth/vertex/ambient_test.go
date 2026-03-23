package vertex

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type fakeAmbientMetadataClient struct {
	projectID  string
	projectErr error
	email      string
	emailErr   error
}

func (f fakeAmbientMetadataClient) ProjectID() (string, error) {
	return f.projectID, f.projectErr
}

func (f fakeAmbientMetadataClient) Email(string) (string, error) {
	return f.email, f.emailErr
}

type fakeAmbientTokenSource struct {
	token *oauth2.Token
	err   error
}

func (f fakeAmbientTokenSource) Token() (*oauth2.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.token == nil {
		return &oauth2.Token{}, nil
	}
	return f.token, nil
}

func TestDiscoverAmbientCredentialsOnGCE(t *testing.T) {
	origClient := newAmbientMetadataClient
	origFind := findAmbientDefaultCredentials
	t.Cleanup(func() {
		newAmbientMetadataClient = origClient
		findAmbientDefaultCredentials = origFind
	})

	newAmbientMetadataClient = func(_ time.Duration) ambientMetadataClient {
		return fakeAmbientMetadataClient{
			projectID: "test-project",
			email:     "vm@example.com",
		}
	}
	findAmbientDefaultCredentials = func(context.Context, ...string) (*google.Credentials, error) {
		return &google.Credentials{
			TokenSource: fakeAmbientTokenSource{token: &oauth2.Token{AccessToken: "ambient-token"}},
		}, nil
	}

	ambient, err := DiscoverAmbientCredentials(context.Background())
	if err != nil {
		t.Fatalf("DiscoverAmbientCredentials() error = %v", err)
	}
	if ambient == nil {
		t.Fatal("DiscoverAmbientCredentials() returned nil credentials")
	}
	if ambient.ProjectID != "test-project" {
		t.Fatalf("ProjectID = %q, want %q", ambient.ProjectID, "test-project")
	}
	if ambient.Email != "vm@example.com" {
		t.Fatalf("Email = %q, want %q", ambient.Email, "vm@example.com")
	}
	if ambient.Location != DefaultAmbientLocation {
		t.Fatalf("Location = %q, want %q", ambient.Location, DefaultAmbientLocation)
	}
}

func TestDiscoverAmbientCredentialsOffGCE(t *testing.T) {
	origClient := newAmbientMetadataClient
	origFind := findAmbientDefaultCredentials
	t.Cleanup(func() {
		newAmbientMetadataClient = origClient
		findAmbientDefaultCredentials = origFind
	})

	newAmbientMetadataClient = func(_ time.Duration) ambientMetadataClient {
		return fakeAmbientMetadataClient{projectErr: errors.New("metadata unavailable")}
	}
	findAmbientDefaultCredentials = func(context.Context, ...string) (*google.Credentials, error) {
		t.Fatal("FindDefaultCredentials should not be called when metadata lookup fails")
		return nil, nil
	}

	ambient, err := DiscoverAmbientCredentials(context.Background())
	if err != nil {
		t.Fatalf("DiscoverAmbientCredentials() error = %v", err)
	}
	if ambient != nil {
		t.Fatalf("DiscoverAmbientCredentials() = %#v, want nil", ambient)
	}
}

func TestDiscoverAmbientCredentialsMetadataTimeout(t *testing.T) {
	origClient := newAmbientMetadataClient
	origFind := findAmbientDefaultCredentials
	t.Cleanup(func() {
		newAmbientMetadataClient = origClient
		findAmbientDefaultCredentials = origFind
	})

	newAmbientMetadataClient = func(_ time.Duration) ambientMetadataClient {
		return fakeAmbientMetadataClient{projectErr: context.DeadlineExceeded}
	}
	findAmbientDefaultCredentials = func(context.Context, ...string) (*google.Credentials, error) {
		t.Fatal("FindDefaultCredentials should not be called when metadata times out")
		return nil, nil
	}

	ambient, err := DiscoverAmbientCredentials(context.Background())
	if err != nil {
		t.Fatalf("DiscoverAmbientCredentials() error = %v", err)
	}
	if ambient != nil {
		t.Fatalf("DiscoverAmbientCredentials() = %#v, want nil", ambient)
	}
}

func TestDiscoverAmbientCredentialsMissingProjectID(t *testing.T) {
	origClient := newAmbientMetadataClient
	origFind := findAmbientDefaultCredentials
	t.Cleanup(func() {
		newAmbientMetadataClient = origClient
		findAmbientDefaultCredentials = origFind
	})

	newAmbientMetadataClient = func(_ time.Duration) ambientMetadataClient {
		return fakeAmbientMetadataClient{projectID: " "}
	}
	findAmbientDefaultCredentials = func(context.Context, ...string) (*google.Credentials, error) {
		return &google.Credentials{
			TokenSource: fakeAmbientTokenSource{token: &oauth2.Token{AccessToken: "ambient-token"}},
		}, nil
	}

	ambient, err := DiscoverAmbientCredentials(context.Background())
	if err == nil {
		t.Fatal("DiscoverAmbientCredentials() error = nil, want error")
	}
	if ambient != nil {
		t.Fatalf("DiscoverAmbientCredentials() = %#v, want nil", ambient)
	}
}

func TestDiscoverAmbientCredentialsDefaultCredentialsFailure(t *testing.T) {
	origClient := newAmbientMetadataClient
	origFind := findAmbientDefaultCredentials
	t.Cleanup(func() {
		newAmbientMetadataClient = origClient
		findAmbientDefaultCredentials = origFind
	})

	newAmbientMetadataClient = func(_ time.Duration) ambientMetadataClient {
		return fakeAmbientMetadataClient{projectID: "test-project"}
	}
	findAmbientDefaultCredentials = func(context.Context, ...string) (*google.Credentials, error) {
		return nil, errors.New("adc unavailable")
	}

	ambient, err := DiscoverAmbientCredentials(context.Background())
	if err == nil {
		t.Fatal("DiscoverAmbientCredentials() error = nil, want error")
	}
	if ambient != nil {
		t.Fatalf("DiscoverAmbientCredentials() = %#v, want nil", ambient)
	}
}

func TestAmbientAccessToken(t *testing.T) {
	origFind := findAmbientDefaultCredentials
	t.Cleanup(func() {
		findAmbientDefaultCredentials = origFind
	})

	findAmbientDefaultCredentials = func(context.Context, ...string) (*google.Credentials, error) {
		return &google.Credentials{
			TokenSource: fakeAmbientTokenSource{token: &oauth2.Token{AccessToken: "ambient-token"}},
		}, nil
	}

	token, err := AmbientAccessToken(context.Background())
	if err != nil {
		t.Fatalf("AmbientAccessToken() error = %v", err)
	}
	if token != "ambient-token" {
		t.Fatalf("AmbientAccessToken() = %q, want %q", token, "ambient-token")
	}
}

func TestAmbientAccessTokenDefaultCredentialsFailure(t *testing.T) {
	origFind := findAmbientDefaultCredentials
	t.Cleanup(func() {
		findAmbientDefaultCredentials = origFind
	})

	findAmbientDefaultCredentials = func(context.Context, ...string) (*google.Credentials, error) {
		return nil, errors.New("adc unavailable")
	}

	token, err := AmbientAccessToken(context.Background())
	if err == nil {
		t.Fatal("AmbientAccessToken() error = nil, want error")
	}
	if token != "" {
		t.Fatalf("AmbientAccessToken() = %q, want empty token", token)
	}
}
