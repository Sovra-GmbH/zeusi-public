# Workspace export sync

Zeusi can import a folder of markdown notes produced by a daily export (`zeusi export-filter`, then `zeusi ingest hq-sync`). Layout: `<root>/<project>/YYYY-MM-DD-<slug>.md`. Each project folder is one source in `config/sources.toml`, which sets the scope. This is a generic import path: point it at your own export folder. Do not commit real notes or names.
