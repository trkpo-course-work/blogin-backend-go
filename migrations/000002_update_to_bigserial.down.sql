ALTER TABLE credentials
    DROP CONSTRAINT IF EXISTS credentials_user_id_fkey;
ALTER TABLE credentials
    ALTER COLUMN id TYPE int;
ALTER TABLE credentials
    ALTER COLUMN user_id TYPE int;
ALTER TABLE users
    ALTER COLUMN id TYPE int;
ALTER TABLE credentials
    ADD CONSTRAINT credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES users ON DELETE cascade;
