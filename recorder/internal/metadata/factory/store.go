package factory

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/netbirdio/netbird/recorder/internal/metadata"
	"github.com/netbirdio/netbird/recorder/internal/metadata/pgsql"
	"github.com/netbirdio/netbird/recorder/internal/metadata/sqlite"
	"github.com/netbirdio/netbird/util/crypt"
)

var ErrUnsupportedEngine = errors.New("unsupported metadata store engine")

const (
	defaultSqliteFile = "recorder.db"
	EnvSqliteFile     = "NB_RECORDER_SQLITE_FILE"
	// EnvPostgresDSN is required when Engine is EnginePostgres.
	EnvPostgresDSN = "NB_RECORDER_POSTGRES_DSN"
)

func New(ctx context.Context, engine metadata.Engine, dataDir string, enc *crypt.FieldEncrypt) (metadata.Store, error) {
	switch engine {
	case metadata.EngineSQLite:
		file := defaultSqliteFile
		if v, ok := os.LookupEnv(EnvSqliteFile); ok && v != "" {
			file = v
		}
		return sqlite.New(dataDir, file, enc)
	case metadata.EnginePostgres:
		dsn, ok := os.LookupEnv(EnvPostgresDSN)
		if !ok || dsn == "" {
			return nil, fmt.Errorf("%s must be set when using the postgres metadata store", EnvPostgresDSN)
		}
		return pgsql.New(ctx, dsn, enc)
	}
	return nil, fmt.Errorf("metadata store doesn't support engine %q: %w", engine, ErrUnsupportedEngine)
}
