package cli

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/redhat-et/skill-trust/pkg/manifest"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect <dir>",
	Short: "Inspect the control files of a signed skill",
	Long: `Inspect the control files of a signed skill.

Reports what is stored under .skill-trust/: the embedded manifest (digest
and file inventory), whether the directory still matches it byte for byte,
every entry in the control directory (flagging anything that is not a
reserved control file), and descriptive signature information (signer
identity or key hint, certificate validity, transparency log entries,
RFC 3161 timestamps).

inspect performs no cryptographic verification and applies no policy; it
reads metadata only. Use verify for enforcement.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]
		w := cmd.OutOrStdout()

		m, err := manifest.LoadControlManifest(dir)
		if err != nil {
			failf("%s is not a signed skill: %v", dir, err)
			return
		}
		digest, err := m.Digest()
		if err != nil {
			failf("computing manifest digest: %v", err)
			return
		}

		executable := 0
		for _, e := range m.Entries {
			if e.Executable {
				executable++
			}
		}

		// Content drift: recomputed manifest vs the signed one.
		contentStatus := "unknown"
		var diffs []manifest.Difference
		observedDigest := ""
		if observed, err := manifest.Create(dir); err != nil {
			contentStatus = fmt.Sprintf("cannot recompute: %v", err)
		} else {
			diffs = manifest.Compare(m, observed)
			if len(diffs) == 0 {
				contentStatus = "matches signed manifest"
			} else {
				contentStatus = fmt.Sprintf("%d difference(s) from signed manifest", len(diffs))
			}
			if d, err := observed.Digest(); err == nil {
				observedDigest = d
			}
		}

		// Control-directory inventory: what would ship in .skill-trust/.
		controlStatus, unexpected := inspectControlDir(dir)

		// Bundle metadata.
		var bi bundleInfo
		raw, err := os.ReadFile(manifest.ControlPath(dir, manifest.BundleFile))
		if err != nil {
			bi.Present = false
		} else {
			var pb protobundle.Bundle
			if err := protojson.Unmarshal(raw, &pb); err != nil {
				failf("signature bundle is not a Sigstore bundle: %v", err)
				return
			}
			bi = describeBundle(&pb)
		}

		if jsonOutput {
			out := struct {
				Manifest        manifest.Manifest       `json:"manifest"`
				Digest          string                  `json:"digest"`
				ExecutableCount int                     `json:"executableCount"`
				ObservedDigest  string                  `json:"observedDigest,omitempty"`
				ContentStatus   string                  `json:"contentStatus"`
				Differences     []manifest.Difference   `json:"differences,omitempty"`
				ControlStatus   string                  `json:"controlStatus"`
				UnexpectedCtrl  []manifest.ControlEntry `json:"unexpectedControlEntries,omitempty"`
				Bundle          *bundleInfo             `json:"bundle"`
			}{
				Manifest:        *m,
				Digest:          digest,
				ExecutableCount: executable,
				ObservedDigest:  observedDigest,
				ContentStatus:   contentStatus,
				Differences:     diffs,
				ControlStatus:   controlStatus,
				UnexpectedCtrl:  unexpected,
				Bundle:          &bi,
			}
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			if err := enc.Encode(out); err != nil {
				failf("encoding output: %v", err)
				return
			}
			return
		}

		fmt.Fprintf(w, "skill:     %s\n", dir)
		fmt.Fprintf(w, "digest:    %s\n", digest)
		fmt.Fprintf(w, "files:     %d (%d executable)\n", len(m.Entries), executable)
		fmt.Fprintf(w, "content:   %s\n", contentStatus)
		fmt.Fprintf(w, "control:   %s\n", controlStatus)
		for _, u := range unexpected {
			fmt.Fprintf(w, "  unexpected: %s (%s)\n", u.Name, u.Kind)
		}
		for _, d := range diffs {
			fmt.Fprintf(w, "  diff:    [%s] %s %s\n", d.Kind, d.Path, d.Details)
		}
		if !bi.Present {
			fmt.Fprintf(w, "bundle:    missing (%s)\n", manifest.ControlPath(dir, manifest.BundleFile))
			return
		}
		fmt.Fprintf(w, "bundle:    %s\n", bi.MediaType)
		if bi.KeyHint != "" {
			fmt.Fprintf(w, "signer:    key (hint %s)\n", bi.KeyHint)
		}
		// Cert metadata is keyed off the certificate, not off a non-empty
		// identity: a cert without URI or email SANs still has an issuer
		// and a validity window worth reporting.
		if bi.HasCert {
			fmt.Fprintf(w, "signer:    keyless\n")
			if bi.Identity != "" {
				fmt.Fprintf(w, "identity:  %s\n", bi.Identity)
			} else {
				fmt.Fprintf(w, "identity:  (certificate has no URI or email SAN)\n")
			}
			if bi.Issuer != "" {
				fmt.Fprintf(w, "issuer:    %s\n", bi.Issuer)
			}
			fmt.Fprintf(w, "cert:      valid %s to %s\n",
				bi.NotBefore.Format(time.RFC3339), bi.NotAfter.Format(time.RFC3339))
		}
		if n := len(bi.TlogEntries); n > 0 {
			fmt.Fprintf(w, "rekor:     %d entr%s, integrated %s\n", n,
				plural(n, "y", "ies"), bi.TlogEntries[0].IntegratedTime.Format(time.RFC3339))
		} else {
			fmt.Fprintf(w, "rekor:     no entries\n")
		}
		if bi.TimestampCount > 0 {
			fmt.Fprintf(w, "timestamp: %d RFC 3161\n", bi.TimestampCount)
		} else {
			fmt.Fprintf(w, "timestamp: none\n")
		}
	},
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// inspectControlDir summarizes the control directory: a human-readable
// status line and the unexpected entries, if any. inspect is
// informational, so an unreadable control directory is reported, never
// fatal.
func inspectControlDir(dir string) (string, []manifest.ControlEntry) {
	unexpected, err := manifest.UnexpectedControlEntries(dir)
	if err != nil {
		return fmt.Sprintf("cannot read: %v", err), nil
	}
	if len(unexpected) == 0 {
		return fmt.Sprintf("only reserved files (%s)", strings.Join(manifest.ReservedControlFiles, ", ")), nil
	}
	return fmt.Sprintf("%d unexpected %s", len(unexpected), plural(len(unexpected), "entry", "entries")), unexpected
}

// bundleInfo is the descriptive metadata inspect reports.
type bundleInfo struct {
	Present        bool       `json:"present"`
	MediaType      string     `json:"mediaType,omitempty"`
	HasCert        bool       `json:"hasCert,omitempty"`
	Identity       string     `json:"identity,omitempty"`
	Issuer         string     `json:"issuer,omitempty"`
	NotBefore      time.Time  `json:"notBefore,omitempty"`
	NotAfter       time.Time  `json:"notAfter,omitempty"`
	KeyHint        string     `json:"keyHint,omitempty"`
	TlogEntries    []tlogInfo `json:"tlogEntries,omitempty"`
	TimestampCount int        `json:"timestampCount,omitempty"`
}

type tlogInfo struct {
	LogID          string    `json:"logId"`
	IntegratedTime time.Time `json:"integratedTime"`
}

// describeBundle extracts presentation-level metadata from a bundle. It
// performs no cryptographic verification.
func describeBundle(pb *protobundle.Bundle) bundleInfo {
	info := bundleInfo{
		Present:   true,
		MediaType: pb.GetMediaType(),
	}

	if hint := pb.GetVerificationMaterial().GetPublicKey().GetHint(); len(hint) > 0 {
		info.KeyHint = string(hint)
	}

	if cert := parseBundleCert(pb); cert != nil {
		info.HasCert = true
		// Identity preference: URI SANs (Fulcio workflow identity) over
		// email SANs; within a type, the certificate's own ordering is
		// stable, so selection is deterministic for a given bundle.
		if len(cert.URIs) > 0 {
			info.Identity = cert.URIs[0].String()
		} else if len(cert.EmailAddresses) > 0 {
			info.Identity = cert.EmailAddresses[0]
		}
		info.Issuer = certIssuer(cert)
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter
	}

	for _, tle := range pb.GetVerificationMaterial().GetTlogEntries() {
		info.TlogEntries = append(info.TlogEntries, tlogInfo{
			LogID:          fmt.Sprintf("%x", tle.GetLogId().GetKeyId()),
			IntegratedTime: time.Unix(tle.GetIntegratedTime(), 0).UTC(),
		})
	}
	info.TimestampCount = len(pb.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps())
	return info
}

// parseBundleCert extracts the signer certificate from bundle
// verification material, if present.
func parseBundleCert(pb *protobundle.Bundle) *x509.Certificate {
	vm := pb.GetVerificationMaterial()
	if vm == nil {
		return nil
	}
	raw := vm.GetCertificate().GetRawBytes()
	if len(raw) == 0 {
		chain := vm.GetX509CertificateChain().GetCertificates()
		if len(chain) == 0 {
			return nil
		}
		raw = chain[0].GetRawBytes()
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil
	}
	return cert
}

// certIssuer reads the Fulcio OIDC issuer extension
// (OID 1.3.6.1.4.1.57264.1.1), preferring the DER-encoded UTF8String form
// and falling back to raw bytes.
func certIssuer(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidFulcioIssuer) {
			continue
		}
		var s string
		if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
			return s
		}
		return string(ext.Value)
	}
	return ""
}

// oidFulcioIssuer is the Fulcio extension carrying the OIDC issuer.
var oidFulcioIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

func init() {
	rootCmd.AddCommand(inspectCmd)
}
