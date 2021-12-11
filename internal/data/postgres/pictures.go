package postgres

import (
	"context"
	"errors"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	"github.com/georgysavva/scany/pgxscan"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

type PicturesRepository struct {
	DB *pgxpool.Pool
}

func (pr *PicturesRepository) Add(ctx context.Context, p *models.Picture) error {
	conn, err := pr.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	stmt := "INSERT INTO pictures (path) VALUES ($1) RETURNING id"
	if err := conn.QueryRow(ctx, stmt, p.Path).Scan(&p.ID); err != nil {
		return err
	}

	return nil
}

func (pr *PicturesRepository) GetByID(ctx context.Context, id int64) (*models.Picture, error) {
	conn, err := pr.DB.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	picture := &models.Picture{}
	stmt := "SELECT id, path FROM pictures WHERE id=$1;"
	if err := pgxscan.Get(ctx, conn, picture, stmt, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNoRecord
		}
		return nil, err
	}

	return picture, nil
}

func (pr *PicturesRepository) Delete(ctx context.Context, id int64) error {
	conn, err := pr.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	stmt := "DELETE FROM pictures WHERE id=$1"
	if _, err := conn.Exec(ctx, stmt, id); err != nil {
		return err
	}

	return nil
}
