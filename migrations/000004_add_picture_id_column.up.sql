ALTER TABLE users
    ADD COLUMN picture_id bigint REFERENCES pictures (id) ON DELETE CASCADE;
