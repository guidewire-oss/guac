//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clearlydefined

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	attestation_license "github.com/guacsec/guac/pkg/certifier/attestation/license"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	justification = "Retrieved from ClearlyDefined"
)

type parser struct {
	pkg                   *generated.PkgInputSpec
	src                   *generated.SourceInputSpec
	collectedCertifyLegal []assembler.CertifyLegalIngest
	hasSourceAt           []assembler.HasSourceAtIngest
}

// NewLegalCertificationParser initializes the parser
func NewLegalCertificationParser() common.DocumentParser {
	return &parser{}
}

// initializeCDParser clears out all values for the next iteration
func (c *parser) initializeCDParser() {
	c.pkg = nil
	c.src = nil
	c.collectedCertifyLegal = make([]assembler.CertifyLegalIngest, 0)
	c.hasSourceAt = make([]assembler.HasSourceAtIngest, 0)
}

// Parse breaks out the document into the graph components
func (c *parser) Parse(ctx context.Context, doc *processor.Document) error {
	c.initializeCDParser()
	statement, err := parseLegalCertifyPredicate(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse slsa predicate: %w", err)
	}
	if err := c.parseSubject(statement); err != nil {
		return fmt.Errorf("unable to parse subject of statement: %w", err)
	}
	if err := c.parseClearlyDefined(ctx, statement); err != nil {
		return fmt.Errorf("unable to parse clearly defined statement: %w", err)
	}
	return nil
}

func parseLegalCertifyPredicate(p []byte) (*attestation_license.ClearlyDefinedStatement, error) {
	predicate := attestation_license.ClearlyDefinedStatement{}
	if err := json.Unmarshal(p, &predicate); err != nil {
		return nil, err
	}
	return &predicate, nil
}

func (c *parser) parseSubject(s *attestation_license.ClearlyDefinedStatement) error {
	for _, sub := range s.Statement.Subject {
		p, err := helpers.PurlToPkg(sub.Uri)
		if err != nil {
			src, err := helpers.GuacSrcIdToSourceInput(sub.Uri)
			if err != nil {
				return fmt.Errorf("failed to parse uri: %s to a package or source with error: %w", sub.Uri, err)
			}
			c.src = src
			return nil
		}
		c.pkg = p
	}
	return nil
}

/* A CertifyLegal node will be created using the “licensed” -> “declared” field from the definition.
The expression will be copied and any license identifiers found will result in linked License noun nodes, created if needed.
Type will be “declared”. Justification will be “Retrieved from ClearlyDefined”. Time will be the current time the information was retrieved from the API.

Similarly a node will be created using the “licensed” -> “facets” -> “core” -> “discovered” -> “expressions” field.
Multiple expressions will be “AND”ed together. Type will be “discovered”, and other fields the same (Time, Justification, License links, etc.).
The “licensed” -> “facets” -> “core” -> “attribution” -> “parties” array will be concatenated and stored in the Attribution field on CertifyLegal.

“described” -> “sourceLocation” can be used to create a HasSourceAt GUAC node. */

// parseClearlyDefined parses the attestation to collect the license information
func (c *parser) parseClearlyDefined(ctx context.Context, s *attestation_license.ClearlyDefinedStatement) error {
	logger := logging.FromContext(ctx)

	if s.Predicate.Definition.Licensed.Declared != "" {
		discoveredLicenses := make([]generated.LicenseInputSpec, 0)
		var discoveredLicenseStr string = ""
		if len(s.Predicate.Definition.Licensed.Facets.Core.Discovered.Expressions) > 0 {
			discoveredLicenseStr = common.CombineLicense(s.Predicate.Definition.Licensed.Facets.Core.Discovered.Expressions)
			discoveredLicenses = append(discoveredLicenses, common.ParseLicenses(discoveredLicenseStr, nil, nil)...)
		}

		declared := assembler.CertifyLegalIngest{
			Declared:   common.ParseLicenses(s.Predicate.Definition.Licensed.Declared, nil, nil),
			Discovered: discoveredLicenses,
			CertifyLegal: &generated.CertifyLegalInputSpec{
				DeclaredLicense:   s.Predicate.Definition.Licensed.Declared,
				DiscoveredLicense: discoveredLicenseStr,
				Justification:     justification,
				TimeScanned:       s.Predicate.Metadata.ScannedOn.UTC(),
			},
		}
		if c.pkg != nil {
			declared.Pkg = c.pkg
		} else if c.src != nil {
			declared.Src = c.src
		} else {
			return fmt.Errorf("package nor source specified for certifyLegal")
		}
		c.collectedCertifyLegal = append(c.collectedCertifyLegal, declared)

		// [GuacDebug] DEBUG POINT 2: Check CertifyLegal predicates
		if declared.Src != nil {
			srcKey := helpers.GetKey[*generated.SourceInputSpec, helpers.SrcIds](declared.Src, helpers.SrcClientKey).NameId
			logger.Debugf("[GuacDebug] [PARSER] CertifyLegal with source: %s", srcKey)
		}
		logger.Debugf("[GuacDebug] [PARSER] Total CertifyLegal predicates: %d", len(c.collectedCertifyLegal))
	} else {
		if len(s.Predicate.Definition.Licensed.Facets.Core.Discovered.Expressions) > 0 {
			discoveredLicense := common.CombineLicense(s.Predicate.Definition.Licensed.Facets.Core.Discovered.Expressions)

			discovered := assembler.CertifyLegalIngest{
				Declared:   []generated.LicenseInputSpec{},
				Discovered: common.ParseLicenses(discoveredLicense, nil, nil),
				CertifyLegal: &generated.CertifyLegalInputSpec{
					DiscoveredLicense: discoveredLicense,
					DeclaredLicense:   "",
					Attribution:       strings.Join(s.Predicate.Definition.Licensed.Facets.Core.Attribution.Parties, ","),
					Justification:     justification,
					TimeScanned:       s.Predicate.Metadata.ScannedOn.UTC(),
				},
			}
			if c.pkg != nil {
				discovered.Pkg = c.pkg
			} else if c.src != nil {
				discovered.Src = c.src
			} else {
				return fmt.Errorf("package nor source specified for certifyLegal")
			}
			c.collectedCertifyLegal = append(c.collectedCertifyLegal, discovered)

			// [GuacDebug] DEBUG POINT 2: Check CertifyLegal predicates
			if discovered.Src != nil {
				srcKey := helpers.GetKey[*generated.SourceInputSpec, helpers.SrcIds](discovered.Src, helpers.SrcClientKey).NameId
				logger.Debugf("[GuacDebug] [PARSER] CertifyLegal with source: %s", srcKey)
			}
			logger.Debugf("[GuacDebug] [PARSER] Total CertifyLegal predicates: %d", len(c.collectedCertifyLegal))
		}
	}

	if s.Predicate.Definition.Described.SourceLocation != nil {
		sourceLocation := s.Predicate.Definition.Described.SourceLocation
		srcInput := helpers.SourceToSourceInput(sourceLocation.Type, sourceLocation.Namespace,
			sourceLocation.Name, &sourceLocation.Revision)

		// [GuacDebug] DEBUG POINT 1: Check what sources are being added
		logger := logging.FromContext(ctx)
		srcKey := helpers.GetKey[*generated.SourceInputSpec, helpers.SrcIds](srcInput, helpers.SrcClientKey).NameId
		logger.Debugf("[GuacDebug] [PARSER] Adding source from SourceLocation: %s", srcKey)

		if c.pkg != nil {
			c.hasSourceAt = append(c.hasSourceAt, assembler.HasSourceAtIngest{
				Pkg:          c.pkg,
				PkgMatchFlag: generated.MatchFlags{Pkg: generated.PkgMatchTypeSpecificVersion},
				Src:          srcInput,
				HasSourceAt: &generated.HasSourceAtInputSpec{
					KnownSince:    s.Predicate.Definition.Meta.Updated.UTC(),
					Justification: justification,
				},
			})
			logger.Debugf("[GuacDebug] [PARSER] Total hasSourceAt predicates: %d", len(c.hasSourceAt))
		}
	}
	return nil
}

func (c *parser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	logger := logging.FromContext(ctx)

	// [GuacDebug] DEBUG POINT 3: Return statement - log all predicates
	preds := &assembler.IngestPredicates{
		CertifyLegal: c.collectedCertifyLegal,
		HasSourceAt:  c.hasSourceAt,
	}

	logger.Debugf("[GuacDebug] [PARSER] Returning predicates: CertifyLegal=%d, HasSourceAt=%d",
		len(preds.CertifyLegal), len(preds.HasSourceAt))

	return preds
}

// GetIdentities gets the identity node from the document if they exist
func (c *parser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (c *parser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}
