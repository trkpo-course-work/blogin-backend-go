package data

import (
	"context"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
)

type UserRepository interface {
	Add(ctx context.Context, user *models.User) error
	GetByID(ctx context.Context, id int64) (*models.User, error)
	GetByLogin(ctx context.Context, login string) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id int) error
}

type PicturesRepository interface {
	Add(ctx context.Context, p *models.Picture) error
	GetByID(ctx context.Context, id int64) (*models.Picture, error)
	Delete(ctx context.Context, id int64) error
}

type CodesRepository interface {
	Add(ctx context.Context, code string, id int64) error
	Get(ctx context.Context, code string) (int64, error)
	Delete(ctx context.Context, code string) error
}

type RefreshTokenRepository interface {
	Add(ctx context.Context, session string, id int64) error
	Get(ctx context.Context, session string) (int64, error)
	Refresh(ctx context.Context, old, new string) error
	Delete(ctx context.Context, session string) error
	DeleteExpired(ctx context.Context) error
	DeleteByUserID(ctx context.Context, id int64) error
}
