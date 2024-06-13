-- migrate:up
CREATE TABLE IF NOT EXISTS web_collections(
    web_item_id char(26),
    collection_id char(26),
    FOREIGN KEY(web_item_id) REFERENCES web_collections(id) on delete set null,
    FOREIGN KEY(collection_id) REFERENCES collections(id) on delete set null
)

-- migrate:down
drop table if exists web_collections
