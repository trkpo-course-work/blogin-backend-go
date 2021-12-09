CREATE TABLE IF NOT EXISTS users_favourites
(
    id bigserial NOT NULL PRIMARY KEY,
    user_id bigint REFERENCES users (id) ON DELETE CASCADE,
    favourite_id bigint REFERENCES users (id) ON DELETE CASCADE
);
