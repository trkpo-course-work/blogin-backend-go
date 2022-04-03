package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
	"github.com/georgysavva/scany/pgxscan"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

type UserRepository struct {
	DB *pgxpool.Pool
}

func (ur *UserRepository) Add(ctx context.Context, user *models.User) error {
	conn, err := ur.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	stmt := "INSERT INTO users (name) VALUES ($1) RETURNING id"
	if err := tx.QueryRow(ctx, stmt, user.FullName).Scan(&user.ID); err != nil {
		return err
	}

	stmt = "INSERT INTO credentials (user_id, login, email, password_hash, confirmed) VALUES ($1, $2, $3, $4, $5)"
	if _, err := tx.Exec(ctx, stmt, user.ID, user.Login, user.Email, user.PasswordHash, user.Confirmed); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr); pgErr.Code == pgerrcode.UniqueViolation {
			switch {
			case strings.Contains(pgErr.ConstraintName, "login"):
				return &models.ErrUserAlreadyExists{Column: "login"}
			case strings.Contains(pgErr.ConstraintName, "email"):
				return &models.ErrUserAlreadyExists{Column: "email"}
			default:
				return err
			}
		}
		return err
	}

	return tx.Commit(ctx)
}

func (ur *UserRepository) GetByID(ctx context.Context, id int64) (*models.User, error) {
	conn, err := ur.DB.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	user := &models.User{}
	stmt := "SELECT u.id, name, login, email, password_hash, confirmed FROM users u JOIN credentials c on u.id = c.user_id WHERE u.id = $1"
	if err := pgxscan.Get(ctx, conn, user, stmt, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNoRecord
		}
		return nil, err
	}

	return user, nil
}

func (ur *UserRepository) GetByLogin(ctx context.Context, login string) (*models.User, error) {
	conn, err := ur.DB.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	user := &models.User{}
	stmt := "SELECT u.id, name, login, email, password_hash, confirmed FROM users u JOIN credentials c on u.id = c.user_id WHERE c.login = $1"
	if err := pgxscan.Get(ctx, conn, user, stmt, login); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNoRecord
		}
		return nil, err
	}

	return user, nil
}

func (ur *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	conn, err := ur.DB.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	user := &models.User{}
	stmt := "SELECT u.id, name, login, email, password_hash, confirmed FROM users u JOIN credentials c on u.id = c.user_id WHERE c.email = $1"
	if err := pgxscan.Get(ctx, conn, user, stmt, strings.ToLower(email)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, models.ErrNoRecord
		}
		return nil, err
	}

	return user, nil
}

func (ur *UserRepository) Update(ctx context.Context, user *models.User) error {
	conn, err := ur.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	stmt := "UPDATE users SET name = $2 WHERE id = $1"
	tag, err := tx.Exec(ctx, stmt, user.ID, user.FullName)
	if err != nil {
		return err
	}

	if tag.RowsAffected() == 0 {
		return models.ErrNoRecord
	}

	stmt = "UPDATE credentials SET login = $2, email = $3, password_hash = $4, confirmed = $5 WHERE user_id = $1"
	tag, err = tx.Exec(ctx, stmt, user.ID, user.Login, user.Email, user.PasswordHash, user.Confirmed)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr); pgErr.Code == pgerrcode.UniqueViolation {
			return models.ErrAlreadyExists
		}
		return err
	}

	if tag.RowsAffected() == 0 {
		return models.ErrNoRecord
	}

	return tx.Commit(ctx)
}

func (ur *UserRepository) Delete(ctx context.Context, id int) error {
	conn, err := ur.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	stmt := "DELETE FROM users WHERE id = $1"
	if _, err := conn.Exec(ctx, stmt, id); err != nil {
		return err
	}

	return nil
}
