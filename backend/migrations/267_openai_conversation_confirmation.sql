-- 历史记录没有成功响应证据，不回填为已确认。
ALTER TABLE openai_conversation_bindings
    ADD COLUMN confirmed BOOLEAN NOT NULL DEFAULT FALSE;
