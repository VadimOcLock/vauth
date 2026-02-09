create table users
(
    id            uuid primary key not null,
    email         varchar unique      not null,
    password_hash varchar             not null,
    created_at    timestamp without time zone default timezone('utc'::text, now()) not null,
    updated_at    timestamp without time zone default timezone('utc'::text, now()) not null,
    is_verified   bool default false
);

CREATE TABLE tokens
(
    id         uuid PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      varchar     NOT NULL,
    revoked    BOOLEAN DEFAULT FALSE,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone default timezone('utc'::text, now()) not null,
    CONSTRAINT unique_token UNIQUE (token, token_type)
);

CREATE TABLE email_confirmations
(
    id         UUID PRIMARY KEY,
    user_id    UUID REFERENCES users (id) ON DELETE CASCADE,
    code       VARCHAR(64) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone default timezone('utc'::text, now()) not null
);