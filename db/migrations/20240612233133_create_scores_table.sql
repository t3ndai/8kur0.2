-- migrate:up
CREATE TABLE IF NOT EXISTS scores(
    web_item_id char(26),
    collecton_id char(26),
    last_updated datetime not null default current_timestamp,
    score float not null,
    FOREIGN KEY(web_item_id) REFERENCES web_collections(id) on delete set null,
    FOREIGN KEY(collecton_id) REFERENCES collections(id) on delete set null
)

-- migrate:down
drop table if exists scores
