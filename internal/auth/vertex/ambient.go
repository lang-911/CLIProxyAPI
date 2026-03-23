package vertex

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2/google"
)

const (
	// AmbientCredentialSource marks runtime-only Vertex auths backed by GCE metadata.
	AmbientCredentialSource = "gce-metadata"
	// DefaultAmbientLocation keeps ambient Vertex aligned with the existing default.
	DefaultAmbientLocation = "global"

	ambientCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
	ambientDiscoveryTimeout   = 1500 * time.Millisecond
)

type ambientMetadataClient interface {
	ProjectID() (string, error)
	Email(serviceAccount string) (string, error)
}

var (
	newAmbientMetadataClient = func(timeout time.Duration) ambientMetadataClient {
		return metadata.NewClient(&http.Client{Timeout: timeout})
	}
	findAmbientDefaultCredentials = google.FindDefaultCredentials
)

// AmbientCredential describes the runtime-only GCE credential context used for Vertex.
type AmbientCredential struct {
	ProjectID string
	Email     string
	Location  string
}

// IsAmbientMetadata reports whether the auth metadata describes a GCE-backed ambient Vertex auth.
func IsAmbientMetadata(meta map[string]any) bool {
	if meta == nil {
		return false
	}
	source, _ := meta["credential_source"].(string)
	return strings.EqualFold(strings.TrimSpace(source), AmbientCredentialSource)
}

// DiscoverAmbientCredentials returns the ambient GCE credential context when the metadata server
// and default Google credentials are both available. When the process is not running on GCE,
// it returns (nil, nil).
func DiscoverAmbientCredentials(ctx context.Context) (*AmbientCredential, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, ambientDiscoveryTimeout)
	defer cancel()

	client := newAmbientMetadataClient(ambientDiscoveryTimeout)
	projectID, err := client.ProjectID()
	if err != nil {
		return nil, nil
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("vertex ambient: missing project_id from GCE metadata")
	}

	creds, err := findAmbientDefaultCredentials(discoveryCtx, ambientCloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("vertex ambient: default credentials unavailable: %w", err)
	}
	if creds == nil || creds.TokenSource == nil {
		return nil, fmt.Errorf("vertex ambient: default credentials missing token source")
	}

	email, errEmail := client.Email("default")
	if errEmail != nil {
		email = ""
	}

	return &AmbientCredential{
		ProjectID: projectID,
		Email:     strings.TrimSpace(email),
		Location:  DefaultAmbientLocation,
	}, nil
}

// AmbientAccessToken returns a bearer token from GCE ambient Google credentials.
func AmbientAccessToken(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	creds, err := findAmbientDefaultCredentials(ctx, ambientCloudPlatformScope)
	if err != nil {
		return "", fmt.Errorf("vertex ambient: default credentials unavailable: %w", err)
	}
	if creds == nil || creds.TokenSource == nil {
		return "", fmt.Errorf("vertex ambient: default credentials missing token source")
	}
	tok, err := creds.TokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("vertex ambient: get access token failed: %w", err)
	}
	return strings.TrimSpace(tok.AccessToken), nil
}
