CREATE TABLE users
(
    id   serial PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE credentials
(
    id            serial PRIMARY KEY,
    user_id       int REFERENCES users (id) ON DELETE CASCADE,
    login         text NOT NULL UNIQUE,
    email         text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    confirmed bool NOT NULL
);
