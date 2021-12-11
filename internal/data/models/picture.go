package models

type Picture struct {
	ID   int64  `db:"id"`
	Path string `db:"path"`
}
