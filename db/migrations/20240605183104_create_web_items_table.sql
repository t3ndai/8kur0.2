-- migrate:up
create table if not exists web_items(
    id char(26) primary key,
    url varchar(255) not null,
    source varchar(255),
    body text,
    user_id char(26),
    age datetime,
    FOREIGN KEY(user_id) REFERENCES users(id) on delete set null ,
    unique(url, user_id)
);

-- migrate:down
drop table if exists web_items
