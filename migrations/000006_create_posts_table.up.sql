CREATE TABLE IF NOT EXISTS posts
(
    id bigserial NOT NULL PRIMARY KEY,
    user_id bigint REFERENCES users (id) ON DELETE CASCADE,
    date_time bigint NOT NULL,
    is_private bool NOT NULL,
    span_json text,
    text text,
    picture_id bigint REFERENCES pictures (id) ON DELETE CASCADE
);
