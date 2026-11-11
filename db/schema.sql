-- Execute uma única vez no SQL Editor de um projeto Neon separado para BCMS95 LAB.
CREATE TABLE IF NOT EXISTS public.lab_workspace (
  id text PRIMARY KEY,
  revision bigint NOT NULL DEFAULT 0,
  data jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT lab_workspace_is_array CHECK (jsonb_typeof(data) = 'array')
);
