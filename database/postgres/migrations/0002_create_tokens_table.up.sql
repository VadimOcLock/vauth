CREATE TABLE tokens
(
    id         uuid PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      varchar     NOT NULL,
    revoked    BOOLEAN DEFAULT FALSE,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone default timezone('utc'::text, now()) not null
);