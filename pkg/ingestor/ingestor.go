//
// Copyright 2023 The GUAC Authors.
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

package ingestor

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	bulk_helpers "github.com/guacsec/guac/pkg/assembler/clients/helpers"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	csub_client "github.com/guacsec/guac/pkg/collectsub/client"
	"github.com/guacsec/guac/pkg/collectsub/collectsub/input"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	parser_common "github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
)

// Synchronously ingest document using GraphQL endpoint
func Ingest(
	ctx context.Context,
	d *processor.Document,
	graphqlEndpoint string,
	transport http.RoundTripper,
	csubClient csub_client.Client,
	scanForVulns bool,
	scanForLicense bool,
	scanForEOL bool,
	scanForDepsDev bool,
) (*bulk_helpers.AssemblerIngestedIDs, error) {
	logger := d.ChildLogger
	// Get pipeline of components
	processorFunc := GetProcessor(ctx)
	ingestorFunc := GetIngestor(ctx, scanForVulns, scanForLicense, scanForEOL, scanForDepsDev)
	collectSubEmitFunc := GetCollectSubEmit(ctx, csubClient)
	assemblerFunc := GetAssembler(ctx, d.ChildLogger, graphqlEndpoint, transport)

	start := time.Now()

	docTree, err := processorFunc(d)
	if err != nil {
		return nil, fmt.Errorf("unable to process doc: %v, format: %v, document: %v", err, d.Format, d.Type)
	}

	predicates, idstrings, err := ingestorFunc(docTree)
	if err != nil {
		return nil, fmt.Errorf("unable to ingest doc tree: %v", err)
	}

	if err := collectSubEmitFunc(idstrings); err != nil {
		logger.Infof("unable to create entries in collectsub server, but continuing: %v", err)
	}

	ingestedIDs, err := assemblerFunc(predicates)
	if err != nil {
		return nil, fmt.Errorf("error assembling graphs for %q : %w", d.SourceInformation.Source, err)
	}

	t := time.Now()
	elapsed := t.Sub(start)
	logger.Infof("[%v] completed doc %+v", elapsed, d.SourceInformation)
	return ingestedIDs, nil
}

func MergedIngest(
	ctx context.Context,
	docs []*processor.Document,
	graphqlEndpoint string,
	transport http.RoundTripper,
	csubClient csub_client.Client,
	scanForVulns bool,
	scanForLicense bool,
	scanForEOL bool,
	scanForDepsDev bool,
) error {
	logger := logging.FromContext(ctx)
	// Get pipeline of components
	processorFunc := GetProcessor(ctx)
	ingestorFunc := GetIngestor(ctx, scanForVulns, scanForLicense, scanForEOL, scanForDepsDev)
	collectSubEmitFunc := GetCollectSubEmit(ctx, csubClient)
	assemblerFunc := GetAssembler(ctx, logger, graphqlEndpoint, transport)

	start := time.Now()

	predicates := make([]assembler.IngestPredicates, 1)
	totalPredicates := 0
	var idstrings []*parser_common.IdentifierStrings

	// [GuacDebug] DEBUG POINT 4: Log start of processing
	logger.Infof("[GuacDebug] [INGESTOR] Starting MergedIngest with %d documents", len(docs))

	for docNum, d := range docs {
		docTree, err := processorFunc(d)
		if err != nil {
			return fmt.Errorf("unable to process doc: %v, format: %v, document: %v", err, d.Format, d.Type)
		}

		preds, idstrs, err := ingestorFunc(docTree)
		if err != nil {
			return fmt.Errorf("unable to ingest doc tree: %v", err)
		}

		// [GuacDebug] DEBUG POINT 5: Log predicates from each document
		logger.Debugf("[GuacDebug] [INGESTOR] Document %d predicates: CertifyLegal=%d, HasSourceAt=%d",
			docNum, len(preds[0].CertifyLegal), len(preds[0].HasSourceAt))

		for i := range preds {
			predicates[0].CertifyScorecard = append(predicates[0].CertifyScorecard, preds[i].CertifyScorecard...)
			predicates[0].IsDependency = append(predicates[0].IsDependency, preds[i].IsDependency...)
			predicates[0].IsOccurrence = append(predicates[0].IsOccurrence, preds[i].IsOccurrence...)
			predicates[0].HasSlsa = append(predicates[0].HasSlsa, preds[i].HasSlsa...)
			predicates[0].CertifyVuln = append(predicates[0].CertifyVuln, preds[i].CertifyVuln...)
			predicates[0].VulnEqual = append(predicates[0].VulnEqual, preds[i].VulnEqual...)
			predicates[0].HasSourceAt = append(predicates[0].HasSourceAt, preds[i].HasSourceAt...)
			predicates[0].CertifyBad = append(predicates[0].CertifyBad, preds[i].CertifyBad...)
			predicates[0].CertifyGood = append(predicates[0].CertifyGood, preds[i].CertifyGood...)
			predicates[0].HasSBOM = append(predicates[0].HasSBOM, preds[i].HasSBOM...)
			predicates[0].HashEqual = append(predicates[0].HashEqual, preds[i].HashEqual...)
			predicates[0].PkgEqual = append(predicates[0].PkgEqual, preds[i].PkgEqual...)
			predicates[0].Vex = append(predicates[0].Vex, preds[i].Vex...)
			predicates[0].PointOfContact = append(predicates[0].PointOfContact, preds[i].PointOfContact...)
			predicates[0].VulnMetadata = append(predicates[0].VulnMetadata, preds[i].VulnMetadata...)
			predicates[0].HasMetadata = append(predicates[0].HasMetadata, preds[i].HasMetadata...)
			predicates[0].CertifyLegal = append(predicates[0].CertifyLegal, preds[i].CertifyLegal...)

			// [GuacDebug] DEBUG POINT 6: Log after merging
			logger.Debugf("[GuacDebug] [INGESTOR] After merge: Total CertifyLegal=%d, HasSourceAt=%d",
				len(predicates[0].CertifyLegal), len(predicates[0].HasSourceAt))

			// [GuacDebug] DEBUG POINT 7: Check for duplicate sources in accumulated predicates
			sourcesSeen := make(map[string]int)
			for _, cl := range predicates[0].CertifyLegal {
				if cl.Src != nil {
					srcKey := helpers.GetKey[*generated.SourceInputSpec, helpers.SrcIds](
						cl.Src, helpers.SrcClientKey).NameId
					sourcesSeen[srcKey]++
				}
			}
			for _, hs := range predicates[0].HasSourceAt {
				if hs.Src != nil {
					srcKey := helpers.GetKey[*generated.SourceInputSpec, helpers.SrcIds](
						hs.Src, helpers.SrcClientKey).NameId
					sourcesSeen[srcKey]++
				}
			}

			for srcKey, count := range sourcesSeen {
				if count > 1 {
					logger.Warnf("⚠️  [INGESTOR] Source appears %d times in predicates: %s", count, srcKey)
				}
			}

			totalPredicates += 1
			// enough predicates have been collected, worth sending them to GraphQL server
			if totalPredicates == 5000 {
				// [GuacDebug] DEBUG POINT 8: Batch processing
				logger.Infof("[GuacDebug] [INGESTOR] Calling assembler with batch of %d predicates", totalPredicates)
				_, err = assemblerFunc(predicates)
				if err != nil {
					return fmt.Errorf("unable to assemble graphs: %v", err)
				}
				// reset counter and predicates
				totalPredicates = 0
				predicates[0] = assembler.IngestPredicates{}
			}
		}
		idstrings = append(idstrings, idstrs...)
	}

	err := collectSubEmitFunc(idstrings)
	if err != nil {
		logger.Infof("unable to create entries in collectsub server, but continuing: %v", err)
	}

	// [GuacDebug] DEBUG POINT 8: Final batch
	logger.Infof("[GuacDebug] [INGESTOR] Calling assembler with final batch (%d predicates)", totalPredicates)

	_, err = assemblerFunc(predicates)
	if err != nil {
		return fmt.Errorf("unable to assemble graphs: %v", err)
	}
	t := time.Now()
	elapsed := t.Sub(start)
	logger.Infof("[%v] completed docs %+v", elapsed, len(docs))
	return nil
}

func GetProcessor(ctx context.Context) func(*processor.Document) (processor.DocumentTree, error) {
	return func(d *processor.Document) (processor.DocumentTree, error) {
		return process.Process(ctx, d)
	}
}

func GetIngestor(ctx context.Context, scanForVulns bool, scanForLicense bool, scanForEOL bool, scanForDepsDev bool) func(processor.DocumentTree) ([]assembler.IngestPredicates, []*parser_common.IdentifierStrings, error) {
	return func(doc processor.DocumentTree) ([]assembler.IngestPredicates, []*parser_common.IdentifierStrings, error) {
		return parser.ParseDocumentTree(ctx, doc, scanForVulns, scanForLicense, scanForEOL, scanForDepsDev)
	}
}

func GetAssembler(
	ctx context.Context,
	childLogger *zap.SugaredLogger,
	graphqlEndpoint string,
	transport http.RoundTripper,
) func([]assembler.IngestPredicates) (*bulk_helpers.AssemblerIngestedIDs, error) {
	httpClient := http.Client{Transport: transport}
	gqlclient := graphql.NewClient(graphqlEndpoint, &httpClient)

	return bulk_helpers.GetBulkAssembler(ctx, childLogger, gqlclient)
}

func GetCollectSubEmit(ctx context.Context, csubClient csub_client.Client) func([]*parser_common.IdentifierStrings) error {
	return func(idstrings []*parser_common.IdentifierStrings) error {
		if csubClient != nil {
			entries := input.IdentifierStringsSliceToCollectEntries(idstrings)
			if len(entries) > 0 {
				if err := csubClient.AddCollectEntries(ctx, entries); err != nil {
					return fmt.Errorf("unable to add collect entries: %v", err)
				}
			}
		}
		return nil
	}
}
