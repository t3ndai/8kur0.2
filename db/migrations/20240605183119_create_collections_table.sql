-- migrate:up
CREATE TABLE IF NOT EXISTS collections(
    id char(26) primary key,
    curator varchar(255),
    created_at datetime default current_timestamp,
    updated_at datetime default current_timestamp,
    user_id char(26),
    visibility boolean,
    FOREIGN KEY(user_id) REFERENCES users(id) on delete set null,
    unique(curator, user_id)
)

-- migrate:down
drop table if exists collections

