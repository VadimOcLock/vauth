-- name: ExistsUserByEmail :one
SELECT EXISTS(
    SELECT 1
    FROM users
    WHERE email = $1
);

-- name: CreateUser :one
INSERT INTO users (id, email, password_hash, created_at, updated_at)
VALUES ($1, $2, $3, timezone('utc', now()), timezone('utc', now()))
RETURNING id;

-- name: FindUserByEmail :one
SELECT *
FROM users
WHERE email = @email
LIMIT 1;

-- name: CreateToken :one
INSERT INTO tokens(id, user_id, token, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: CreateEmailConfirmation :one
INSERT INTO email_confirmations(id, user_id, code, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: FindUserByConfirmationCode :one
SELECT u.id, u.email, u.password_hash, u.created_at, u.updated_at, u.is_verified
FROM users u
WHERE id = (SELECT ec.user_id FROM email_confirmations ec WHERE code = $1);

-- name: UpdateUserAsVerified :one
UPDATE users
SET is_verified = true,
    updated_at = timezone('utc', NOW())
WHERE email = $1
RETURNING TRUE AS updated;

-- name: UpdateUserPassword :one
UPDATE users
SET password_hash = $1,
    updated_at = timezone('utc', NOW())
WHERE email = $2
RETURNING TRUE AS updated;
