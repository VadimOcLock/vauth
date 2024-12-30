create table users
(
    id            uuid primary key not null,
    email         text unique      not null,
    password_hash text             not null,
    created_at    timestamp without time zone default timezone('utc'::text, now()) not null,
    updated_at    timestamp without time zone default timezone('utc'::text, now()) not null,
    permissions   jsonb,
    is_active     bool default true,
    is_verified   bool default false
);