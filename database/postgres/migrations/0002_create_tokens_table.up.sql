CREATE TABLE tokens
(
    id         uuid PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      varchar     NOT NULL,
    token_type VARCHAR(50) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone default timezone('utc'::text, now()) not null,
    CONSTRAINT unique_token UNIQUE (token, token_type)
);