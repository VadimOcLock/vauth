-- name: ExistsUserByEmail :one
SELECT EXISTS(
    SELECT 1
    FROM users
    WHERE email = $1
);

-- name: CreateUser :one
INSERT INTO users (id, email, password_hash, permissions, created_at, updated_at)
VALUES ($1, $2, $3, $4::jsonb, timezone('utc', now()), timezone('utc', now()))
    RETURNING id;

-- name: FindUserByEmail :one
SELECT *
FROM users
WHERE email = @email
    LIMIT 1;