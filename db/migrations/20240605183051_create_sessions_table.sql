-- migrate:up
create table if not exists sessions(
    id char(26) primary key,
    user_id char(20) not null,
    expires_at datetime not null,
    FOREIGN KEY(user_id) references users(id) on delete cascade
);

-- migrate:down
drop table if exists sessions
