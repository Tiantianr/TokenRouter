import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import PromptAuditView from '../PromptAuditView.vue'
import type { PromptAuditConfig, PromptAuditRuntime } from '../types'
import { DEFAULT_BLOCKING_REVIEW_MODULES, DEFAULT_DEEP_REVIEW_MODULES, SCANNER_CATALOG } from '../viewModel'

const mocks = vi.hoisted(() => ({
  getConfig: vi.fn(), getPassRetention: vi.fn(), getRuntime: vi.fn(), listGroups: vi.fn(), listEvents: vi.fn(),
  showSuccess: vi.fn(), showError: vi.fn(),
}))

vi.mock('../api', () => ({ default: mocks }))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showSuccess: mocks.showSuccess, showError: mocks.showError }) }))
vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ locale: { value: 'zh' }, t: (key: string) => key }) }
})

const config = (): PromptAuditConfig => ({
  enabled: true, blocking_enabled: true, blocking_latest_turn_only: false,
  blocking_review_modules: { ...DEFAULT_BLOCKING_REVIEW_MODULES }, deep_review_modules: { ...DEFAULT_DEEP_REVIEW_MODULES },
  allow_receipt_ttl_seconds: 3600, effective_mode: 'blocking', strategy: 'priority', worker_count: 32,
  queue_capacity: 32768, scanners: SCANNER_CATALOG.map(({ id }) => id), all_groups: false, group_ids: [4, 5, 7, 13], blocking_exempt_user_ids: [],
  endpoints: [{ id: 'guard-1', name: 'Guard', protocol: 'openai_compatible', base_url: 'https://guard.example.test/v1', model: 'guard', timeout_ms: 3000, input_limit: 200000, enabled: true, has_token: true, token_status: 'configured' }],
  config_version: 55, updated_at: '2026-08-30T00:00:00Z', updated_by: 1, change_summary: '{}',
})

const runtime = (): PromptAuditRuntime => ({
  process_status: 'running', effective_mode: 'blocking', expected_config_version: 55, active_config_version: 55,
  worker_total: 32, worker_active: 32, queue_capacity: 32768,
  queue: { staging: 0, queued: 0, processing: 0, retry: 0, done: 1, failed: 0, active: 0 },
  processed_total: 1, failed_total: 0, enqueued_total: 1, dropped_total: 0,
  extraction_attempted: 1, extraction_succeeded: 1, extraction_empty: 0, extraction_failed: 0,
  allow_receipt_hits: 0, allow_receipt_misses: 1, allow_receipt_writes: 1, allow_receipt_errors: 0,
  recovery_required_sync: 0, recovery_required_async: 0, recovery_cleared: 0, recovery_retained: 0, recovery_errors: 0,
  database_status: 'ok', redis_status: 'ok', endpoints: {},
  guard_metrics: { total: 1, allowed: 1, flagged: 0, blocked: 0, unavailable: 0, invalid: 0, timeouts: 0, failovers: 0, bulkhead_full: 0, record_failed: 0, failure_allowed: 0 },
})

describe('Prompt Audit full render', () => {
  beforeEach(() => {
    mocks.getConfig.mockResolvedValue(config())
    mocks.getPassRetention.mockResolvedValue({ revision: 1, user_ids: null, updated_at: '', updated_by: 0 })
    mocks.getRuntime.mockResolvedValue(runtime())
    mocks.listGroups.mockResolvedValue([])
    mocks.listEvents.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
  })

  it('renders events and configuration with real child components', async () => {
    const wrapper = mount(PromptAuditView, { global: { stubs: { AppLayout: { template: '<div><slot /></div>' } } } })
    await flushPromises()
    expect(wrapper.get('[data-test="tab-panel-events"]').isVisible()).toBe(true)
    await wrapper.get('[data-test="tab-config"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="tab-panel-config"]').isVisible()).toBe(true)
    expect(wrapper.text()).toContain('admin.promptAudit.retention.title')
  })
})
