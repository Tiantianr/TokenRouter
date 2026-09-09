import { describe, expect, it } from 'vitest'
import type { PromptAuditConfig } from '../types'
import {
  buildUpdateRequest,
  configToDraft,
  draftFingerprint,
  emptyEventFilters,
  eventFilterPayload,
  hasExplicitDeleteRange,
  SCANNER_CATALOG,
} from '../viewModel'

const config = (): PromptAuditConfig => ({
  enabled: true,
  blocking_enabled: false,
  blocking_latest_turn_only: false,
  blocking_review_modules: {
    system: true, assistant: false, reasoning: false, prompt_variables: true,
    tool_definitions: true, tool_calls: false, tool_outputs: false,
  },
  deep_review_modules: {
    system: true, assistant: true, reasoning: true, prompt_variables: true,
    tool_definitions: true, tool_calls: true, tool_outputs: true,
  },
  allow_receipt_ttl_seconds: 3600,
  effective_mode: 'async_audit',
  strategy: 'priority',
  worker_count: 4,
  queue_capacity: 100,
  scanners: SCANNER_CATALOG.map((item) => item.id),
  all_groups: true,
  group_ids: [],
  blocking_exempt_user_ids: [],
  endpoints: [{
    id: 'guard-1', name: 'Guard One', protocol: 'openai_compatible', base_url: 'http://127.0.0.1:8000',
    model: 'sileader/qwen3guard:0.6b', timeout_ms: 3000, input_limit: 4000, enabled: true,
    has_token: true, token_status: 'configured',
  }],
  config_version: 7,
  updated_at: '2026-07-16T00:00:00Z',
  updated_by: 1,
  change_summary: '{}',
})

describe('Prompt Audit view model', () => {
  it('normalizes legacy null collections from the public config', () => {
    const legacy = { ...config(), group_ids: null, blocking_exempt_user_ids: null, scanners: null, endpoints: null } as unknown as PromptAuditConfig
    expect(configToDraft(legacy)).toMatchObject({ group_ids: [], blocking_exempt_user_ids: [], scanners: [], endpoints: [] })
  })

  it('models all nine official input scanners', () => {
    expect(SCANNER_CATALOG).toHaveLength(9)
    expect(SCANNER_CATALOG.map((item) => item.id)).toContain('suicide_and_self_harm')
  })

  it('keeps, replaces, or explicitly clears a saved token without copying plaintext from the server', () => {
    const draft = configToDraft(config())
    expect(draft.endpoints[0].token).toBe('')
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: undefined, clear_token: false })

    draft.endpoints[0].token = 'temporary-canary-token'
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: 'temporary-canary-token', clear_token: false })

    draft.endpoints[0].token = ''
    draft.endpoints[0].clear_token = true
    expect(buildUpdateRequest(draft).endpoints[0]).toMatchObject({ token: undefined, clear_token: true })
  })

  it('saves independent synchronous and deep-review modules', () => {
    const draft = configToDraft(config())
    draft.blocking_review_modules.assistant = true
    draft.deep_review_modules.tool_outputs = false
    expect(buildUpdateRequest(draft)).toMatchObject({
      blocking_review_modules: { assistant: true, tool_outputs: false },
      deep_review_modules: { assistant: true, tool_outputs: false },
    })
  })

  it('saves blocking-exempt users in canonical order', () => {
    const draft = configToDraft(config())
    draft.blocking_exempt_user_ids = [9, 3]
    expect(buildUpdateRequest(draft).blocking_exempt_user_ids).toEqual([3, 9])
  })

  it('defaults and saves the incremental Allow receipt TTL', () => {
    const legacy = { ...config(), allow_receipt_ttl_seconds: undefined } as unknown as PromptAuditConfig
    expect(configToDraft(legacy).allow_receipt_ttl_seconds).toBe(3600)
    const draft = configToDraft(config())
    draft.allow_receipt_ttl_seconds = 7200
    expect(buildUpdateRequest(draft).allow_receipt_ttl_seconds).toBe(7200)
  })

  it('drops the obsolete failure-allow switch from legacy config and updates', () => {
    const legacy = { ...config(), allow_on_guard_unavailable: false } as unknown as PromptAuditConfig
    const draft = configToDraft(legacy)
    expect(draft).not.toHaveProperty('allow_on_guard_unavailable')
    expect(buildUpdateRequest(draft)).not.toHaveProperty('allow_on_guard_unavailable')
  })

  it('tracks dirty state from the full normalized save payload', () => {
    const original = configToDraft(config())
    const changed = configToDraft(config())
    expect(draftFingerprint(changed)).toBe(draftFingerprint(original))
    changed.queue_capacity += 1
    expect(draftFingerprint(changed)).not.toBe(draftFingerprint(original))
  })

  it('requires a valid explicit range and sends canonical ISO timestamps for filter deletion', () => {
    const filters = emptyEventFilters()
    expect(hasExplicitDeleteRange(filters)).toBe(false)
    filters.start_at = '2026-07-15T10:00'
    filters.end_at = '2026-07-16T10:00'
    filters.group_id = '9'
    filters.client_ip = '203.0.113.42'
    filters.execution_mode = 'async_deep'
    expect(hasExplicitDeleteRange(filters)).toBe(true)
    expect(eventFilterPayload(filters)).toMatchObject({
      group_id: 9,
      client_ip: '203.0.113.42',
      execution_mode: 'async_deep',
      start_at: new Date(filters.start_at).toISOString(),
      end_at: new Date(filters.end_at).toISOString(),
    })
  })
})
