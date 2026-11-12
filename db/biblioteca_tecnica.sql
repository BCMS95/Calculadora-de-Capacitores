-- A API cria esta tabela automaticamente no Neon na primeira consulta.
-- SQL opcional para instalação administrativa ou revisão de estrutura.
CREATE TABLE IF NOT EXISTS public.lab_documents (
 id text PRIMARY KEY,
 title text NOT NULL,
 category text NOT NULL,
 code text NOT NULL DEFAULT '',
 revision text NOT NULL DEFAULT '',
 description text NOT NULL DEFAULT '',
 filename text NOT NULL,
 bytes integer NOT NULL,
 sha256 text NOT NULL,
 content bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
