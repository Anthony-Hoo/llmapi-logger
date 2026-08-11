-- Parser version 2 adds the encrypted protocol-neutral conversation view.
-- Requeue version 1 results once so existing audit evidence, including prior
-- streaming requests, is rebuilt by the normal bounded parser worker.
UPDATE audit_records
SET parse_status = 'pending'
WHERE ended_at_ns IS NOT NULL
  AND forward_status <> 'rejected'
  AND parser_name IN (
      'openai.chat_completions',
      'openai.completions',
      'openai.responses',
      'openai.responses_compact',
      'anthropic.messages',
      'gemini.generate_content',
      'gemini.stream_generate_content'
  )
  AND audit_id IN (
      SELECT audit_id
      FROM parsed_results
      WHERE parser_version = '1'
  );
