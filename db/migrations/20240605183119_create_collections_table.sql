-- migrate:up
CREATE TABLE IF NOT EXISTS collections(
    id char(26) primary key,
    user_id char(26),
    curator varchar(255) not null,
    data jsonb,
    FOREIGN KEY(user_id) REFERENCES users(id) on delete set null,
    unique(curator, user_id)
)

-- migrate:down
drop table if exists collections
