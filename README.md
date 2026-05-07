# The KChat Rust SDK

This repo contains SDK written in Rust that supports specific logics for KChat.

## Debug MLS Sqlite
```
DB_PATH="/path/to/client.sqlite3"; \
GROUP_ID="083623ce-6372-47ec-ad4d-758589e5d49a@conference.prod-next.kchat.com"; \
OUT="openmls_selected_group_data.json"; \
CODES=$(printf '%s' "$GROUP_ID" | od -An -tu1 | tr -s ' ' '\n' | sed '/^$/d' | paste -sd, -); \
sqlite3 "$DB_PATH" -batch -noheader "
WITH selected AS (
  SELECT data_type, CAST(group_data AS TEXT) AS group_data_json
  FROM openmls_group_data
  WHERE CAST(group_id AS TEXT) LIKE '%$CODES%'
    AND data_type IN ('context','group_epoch_secrets','confirmation_tag')
)
SELECT COALESCE(json_group_object(data_type, json(group_data_json)), '{}')
FROM selected;
" > "$OUT"; \
echo "Wrote $OUT"
```
