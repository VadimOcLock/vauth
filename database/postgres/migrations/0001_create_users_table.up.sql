create table users
(
    id            uuid primary key not null,
    email         varchar unique      not null,
    password_hash varchar             not null,
    created_at    timestamp without time zone default timezone('utc'::text, now()) not null,
    updated_at    timestamp without time zone default timezone('utc'::text, now()) not null,
    is_verified   bool default false
);