wire:
	wire ./cmd/auth-server

DB_DSN=postgres://postgres:bloginpass@localhost/postgres?sslmode=disable

migrate_up:
	migrate -path=./migrations -database=${DB_DSN} up ${VERSION}

migrate_down:
	migrate -path=./migrations -database=${DB_DSN} down ${VERSION}

migrate_force:
	migrate -path=./migrations -database=${DB_DSN} force ${VERSION}

migrate_create:
	migrate create -seq -ext=.sql -dir=./migrations ${NAME}
