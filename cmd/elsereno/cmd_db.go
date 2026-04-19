package main

import (
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	"local/elsereno/internal/db"
)

func newDbCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database operations (migrate, status, verify)",
	}
	cmd.AddCommand(newDbMigrateCmd())
	cmd.AddCommand(newDbStatusCmd())
	cmd.AddCommand(newDbVerifyCmd())
	return cmd
}

func newDbMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply goose migrations",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "up",
		Short: "Apply every pending migration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withPool(cmd, func(cfg config.Config) error {
				pool, err := openPool(cmd, cfg)
				if err != nil {
					return err
				}
				defer pool.Close()
				if err := db.MigrateUp(cmd.Context(), pool); err != nil {
					return fail(core.ExitSoftware, err)
				}
				cmd.Println("migrations applied")
				return nil
			})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "down",
		Short: "Roll back the most recent migration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withPool(cmd, func(cfg config.Config) error {
				pool, err := openPool(cmd, cfg)
				if err != nil {
					return err
				}
				defer pool.Close()
				if err := db.MigrateDown(cmd.Context(), pool); err != nil {
					return fail(core.ExitSoftware, err)
				}
				cmd.Println("rollback applied")
				return nil
			})
		},
	})
	return cmd
}

func newDbStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report applied vs pending migrations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withPool(cmd, func(cfg config.Config) error {
				pool, err := openPool(cmd, cfg)
				if err != nil {
					return err
				}
				defer pool.Close()
				if err := db.MigrateStatus(cmd.Context(), pool); err != nil {
					return fail(core.ExitSoftware, err)
				}
				return nil
			})
		},
	}
}

func newDbVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Ensure the database schema is reachable and at a known version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withPool(cmd, func(cfg config.Config) error {
				pool, err := openPool(cmd, cfg)
				if err != nil {
					return err
				}
				defer pool.Close()
				if err := db.Verify(cmd.Context(), pool); err != nil {
					return fail(core.ExitSoftware, err)
				}
				cmd.Println("ok")
				return nil
			})
		},
	}
}

// withPool loads config and hands it to fn. Extracted so every db
// subcommand has the same error shape.
func withPool(_ *cobra.Command, fn func(config.Config) error) error {
	cfg, _, err := loadConfig()
	if err != nil {
		return fail(core.ExitConfig, err)
	}
	return fn(cfg)
}

// openPool constructs a pgxpool from config + DATABASE_URL.
func openPool(cmd *cobra.Command, cfg config.Config) (*pgxpool.Pool, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fail(core.ExitConfig, fmt.Errorf("DATABASE_URL is not set; see .env.example"))
	}
	p, err := db.New(cmd.Context(), dsn, cfg.Database.TLSRequired, cfg.Database.MaxConns)
	if err != nil {
		return nil, fail(core.ExitUnavail, err)
	}
	return p, nil
}
