-- migrate:up
CREATE TABLE IF NOT EXISTS users(
    id char(26) primary key,
    email varchar(255) unique not null,
    username varchar(255) unique not null,
    password_digest varchar(255) not null,
    created_at datetime default current_timestamp,
    updated_at datetime default current_timestamp
)

-- migrate:down
drop table if exists users;