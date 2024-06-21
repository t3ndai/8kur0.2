/* this might get outdated == if dev machine does not have pgdump */
CREATE TABLE IF NOT EXISTS "schema_migrations" (version varchar(128) primary key);
CREATE TABLE users(
    id char(26) primary key,
    email varchar(255) unique not null,
    username varchar(255) unique not null,
    password_digest varchar(255) not null,
    created_at datetime default current_timestamp,
    updated_at datetime default current_timestamp
);
CREATE TABLE sessions(
    id char(26) primary key,
    user_id char(20) not null,
    expires_at datetime not null,
    FOREIGN KEY(user_id) references users(id) on delete cascade
);
CREATE TABLE web_items(
    id char(26) primary key,
    url varchar(255) not null,
    source varchar(255),
    body text,
    user_id char(26),
    age datetime,
    FOREIGN KEY(user_id) REFERENCES users(id) on delete set null ,
    unique(url, user_id)
);
CREATE TABLE collections(
    id char(26) primary key,
    curator varchar(255),
    created_at datetime default current_timestamp,
    updated_at datetime default current_timestamp,
    user_id char(26),
    visibility boolean,
    FOREIGN KEY(user_id) REFERENCES users(id) on delete set null,
    unique(curator, user_id)
);
CREATE TABLE web_collections(
    web_item_id char(26),
    collection_id char(26),
    FOREIGN KEY(web_item_id) REFERENCES web_collections(id) on delete set null,
    FOREIGN KEY(collection_id) REFERENCES collections(id) on delete set null
);
CREATE TABLE scores(
    web_item_id char(26),
    collecton_id char(26),
    last_updated datetime not null default current_timestamp,
    score float not null,
    FOREIGN KEY(web_item_id) REFERENCES web_collections(id) on delete set null,
    FOREIGN KEY(collecton_id) REFERENCES collections(id) on delete set null
);
-- Dbmate schema migrations
INSERT INTO "schema_migrations" (version) VALUES
  ('20240605183037'),
  ('20240605183051'),
  ('20240605183104'),
  ('20240605183119'),
  ('20240612232555'),
  ('20240612233133');
