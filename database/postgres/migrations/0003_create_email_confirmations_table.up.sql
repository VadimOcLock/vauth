CREATE TABLE email_confirmations
(
    id         UUID PRIMARY KEY,
    user_id    UUID REFERENCES users (id) ON DELETE CASCADE,
    code       VARCHAR(64) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone default timezone('utc'::text, now()) not null
);