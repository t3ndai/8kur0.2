-- migrate:up
create table if not exists web_items(
    id char(26) primary key,
    user_id char(26),
    collection_id char(26) not null,
    url varchar(255),
    data jsonb,
    FOREIGN KEY(user_id) REFERENCES users(id) on delete set null,
    UNIQUE(collection_id, url)
);

-- migrate:down
drop table if exists web_items
