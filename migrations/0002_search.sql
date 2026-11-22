-- 0002_search.sql — search indexes on zeusi.chunks (PLAN.md KTD2, KTD6, U2).
-- HNSW over halfvec(1536), cosine, pgvector defaults m=16 ef_construction=64.
-- Partial on embed_model so a later model can be indexed beside the old one.
-- Query side: SET hnsw.ef_search = 100; SET hnsw.iterative_scan = relaxed_order;
-- and filter WHERE embed_model = 'openai/text-embedding-3-small@1536'.

CREATE INDEX chunks_hnsw_te3s ON zeusi.chunks
  USING hnsw (embedding halfvec_cosine_ops) WITH (m = 16, ef_construction = 64)
  WHERE embed_model = 'openai/text-embedding-3-small@1536';

-- Full text, 'simple' config (notes mix English and German).
CREATE INDEX chunks_tsv ON zeusi.chunks USING gin (tsv);

CREATE INDEX chunks_scope_ts ON zeusi.chunks (scope, source_ts DESC);
CREATE INDEX chunks_note_id     ON zeusi.chunks (note_id)     WHERE note_id IS NOT NULL;
CREATE INDEX chunks_fact_id     ON zeusi.chunks (fact_id)     WHERE fact_id IS NOT NULL;
CREATE INDEX chunks_decision_id ON zeusi.chunks (decision_id) WHERE decision_id IS NOT NULL;
CREATE INDEX chunks_episode_id  ON zeusi.chunks (episode_id)  WHERE episode_id IS NOT NULL;
CREATE INDEX chunks_text_sha    ON zeusi.chunks (text_sha256, embed_model);  -- vector reuse by chunk sha

CREATE INDEX pr_reviews_pr ON zeusi.pr_reviews (repo, number, reviewed_at DESC);
CREATE INDEX decisions_said_at ON zeusi.decisions (said_at DESC);
CREATE INDEX facts_subject ON zeusi.facts (subject) WHERE superseded_by IS NULL;
