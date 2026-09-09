import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, nextTick } from 'vue'
import Select from '@/components/common/Select.vue'
import { mount } from '@vue/test-utils'
import EndpointPool from '../components/EndpointPool.vue'
import PolicyPanel from '../components/PolicyPanel.vue'
import EventWorkspace from '../components/EventWorkspace.vue'
import EventDetailDialog from '../components/EventDetailDialog.vue'
import UserAnalysisDialog from '../components/UserAnalysisDialog.vue'
import FilterDeleteDialog from '../components/FilterDeleteDialog.vue'
import PassEventCleanupDialog from '../components/PassEventCleanupDialog.vue'
import RuntimeOverview from '../components/RuntimeOverview.vue'
import type { PromptAuditDraft, PromptAuditEndpointDraft, PromptAuditEvent, PromptAuditRuntime, PromptEventFilters } from '../types'
import { DEFAULT_BLOCKING_REVIEW_MODULES, DEFAULT_DEEP_REVIEW_MODULES, emptyEventFilters, resolveDeleteRangeFilters, SCANNER_CATALOG } from '../viewModel'

const { downloadEventContext, showError } = vi.hoisted(() => ({
  downloadEventContext: vi.fn(),
  showError: vi.fn(),
}))

vi.mock('../api', () => ({ downloadEventContext }))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showError }) }))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ locale: { value: 'en' }, t: (key: string, params?: Record<string, unknown>) => key.replace(/\{(\w+)\}/g, (_, token) => String(params?.[token] ?? `{${token}}`)) }) }
})

const DialogStub = defineComponent({ props: ['show', 'title'], emits: ['close'], template: '<div v-if="show" data-test="dialog"><slot /><slot name="footer" /></div>' })
const PaginationStub = defineComponent({ props: ['total', 'page', 'pageSize'], emits: ['update:page', 'update:pageSize'], template: '<div data-test="pagination" />' })
const UserSelectorStub = defineComponent({
  props: ['modelValue'], emits: ['update:modelValue'],
  template: '<button type="button" data-test="pick-user" @click="$emit(\'update:modelValue\', [42])">pick</button>',
})

const endpoint = (): PromptAuditEndpointDraft => ({
  id: 'guard-1', name: 'Guard One', protocol: 'openai_compatible', base_url: 'http://127.0.0.1:8000',
  model: 'guard-model', timeout_ms: 3000, input_limit: 4000, enabled: true,
  has_token: true, token_status: 'configured', token: '', clear_token: false,
})

describe('Prompt Audit components', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('surfaces canonical content extraction outcomes and highlights failures', () => {
    const runtime: PromptAuditRuntime = {
      process_status: 'running', effective_mode: 'blocking', expected_config_version: 7, active_config_version: 7,
      worker_total: 4, worker_active: 1, queue_capacity: 100,
      queue: { staging: 0, queued: 0, processing: 1, retry: 0, done: 5, failed: 0, active: 1 },
      processed_total: 5, failed_total: 0, enqueued_total: 5, dropped_total: 0,
      extraction_attempted: 7, extraction_succeeded: 5, extraction_empty: 1, extraction_failed: 1,
      allow_receipt_hits: 3, allow_receipt_misses: 2, allow_receipt_writes: 1, allow_receipt_errors: 0,
      recovery_required_sync: 2, recovery_required_async: 1, recovery_cleared: 1, recovery_retained: 1, recovery_errors: 0,
      last_processed_at: '2026-07-16T00:05:00Z', last_error_at: '2026-07-16T00:01:00Z',
      last_error_code: 'prompt_guard_unavailable', last_error_message: 'Prompt Guard unavailable',
      database_status: 'ok', redis_status: 'ok', endpoints: {},
      guard_metrics: { total: 1, allowed: 1, flagged: 0, blocked: 0, unavailable: 0, invalid: 0, timeouts: 0, failovers: 0, bulkhead_full: 0, record_failed: 0, failure_allowed: 0 },
    }
    const wrapper = mount(RuntimeOverview, { props: { runtime, loading: false, error: '' } })

    expect(wrapper.get('[data-test="extraction-metrics"]').text()).toContain('admin.promptAudit.runtime.extractionMetrics')
    expect(wrapper.get('[data-test="extraction-metric-attempted"]').text()).toContain('7')
    expect(wrapper.get('[data-test="extraction-metric-succeeded"]').text()).toContain('5')
    expect(wrapper.get('[data-test="extraction-metric-empty"]').text()).toContain('1')
    expect(wrapper.get('[data-test="extraction-metric-failed"]').text()).toContain('1')
    expect(wrapper.get('[data-test="extraction-metric-failed"] dd').classes()).toContain('text-red-700')
    expect(wrapper.text()).toContain('admin.promptAudit.runtime.lastProcessed')
    expect(wrapper.text()).toContain('admin.promptAudit.runtime.lastError')
    expect(wrapper.text()).toContain('prompt_guard_unavailable')
    expect(wrapper.text()).toContain('admin.promptAudit.runtime.allowReceiptTotals')
    expect(wrapper.text()).toContain('admin.promptAudit.runtime.recoveryTotals')
  })

  it('renders an ephemeral selected-session analysis report', () => {
    const wrapper = mount(UserAnalysisDialog, {
      props: {
        show: true, loading: false, error: '',
        analysis: {
          user_id: 7, username: 'alice', user_email: 'alice@example.test', session_key: 'a'.repeat(64), session_source: 'client_session',
          record_count: 2, first_record_at: '2026-07-16T00:00:00Z', last_record_at: '2026-07-16T00:05:00Z',
          guard_endpoint_id: 'guard-1', guard_endpoint_name: 'Guard', guard_model: 'guard-model', generated_at: '2026-07-16T00:06:00Z', report: 'risk report',
        },
      },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get('[data-test="user-analysis-report"]').text()).toBe('risk report')
    expect(wrapper.text()).toContain('admin.promptAudit.analysis.session')
    expect(wrapper.text()).toContain('aaaaaaaa...aaaaaaaa')
  })

  it('edits a saved endpoint with blank-secret keep, explicit clear, replacement, and probe actions', async () => {
    const wrapper = mount(EndpointPool, {
      props: { endpoints: [endpoint()], probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.text()).toContain('admin.promptAudit.pool.configured')
    const edit = wrapper.findAll('button').find((button) => button.text().includes('common.edit'))
    expect(edit).toBeTruthy()
    await edit!.trigger('click')
    const token = wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.apiKey"]')
    expect(token.element.value).toBe('')
    expect(token.attributes('placeholder')).toContain('admin.promptAudit.pool.keepSecret')
    expect(wrapper.text()).toContain('admin.promptAudit.pool.timeoutRange')
    expect(wrapper.text()).toContain('admin.promptAudit.pool.inputLimitRange')
    expect(wrapper.text()).toContain('admin.promptAudit.pool.inputLimitBehavior')
    expect(wrapper.get('[aria-label="admin.promptAudit.pool.inputLimit"]').attributes('max')).toBe('500000')

    await wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.clearSecret"]').setValue(true)
    await token.setValue('replacement-canary')
    await wrapper.get('[data-test="save-endpoint"]').trigger('click')
    const updated = wrapper.emitted('update:endpoints')?.at(-1)?.[0] as PromptAuditEndpointDraft[]
    expect(updated[0]).toMatchObject({ token: 'replacement-canary', clear_token: false })

    const probe = wrapper.findAll('button').find((button) => button.text().includes('admin.promptAudit.pool.probe'))
    await probe!.trigger('click')
    expect(wrapper.emitted('probe')?.[0]?.[0]).toMatchObject({ id: 'guard-1' })
  })

  it('surfaces an undecryptable saved credential and prompts for re-entry', async () => {
    const invalidEndpoint = { ...endpoint(), token_status: 'invalid' }
    const wrapper = mount(EndpointPool, {
      props: { endpoints: [invalidEndpoint], probeResults: {}, probingIds: [] },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.text()).toContain('admin.promptAudit.pool.invalid')
    expect(wrapper.text()).not.toContain('admin.promptAudit.pool.configured')

    const edit = wrapper.findAll('button').find((button) => button.text().includes('common.edit'))
    await edit!.trigger('click')
    const token = wrapper.get<HTMLInputElement>('[aria-label="admin.promptAudit.pool.apiKey"]')
    expect(token.attributes('placeholder')).toContain('admin.promptAudit.pool.reenterSecret')
  })

  it('reorders endpoint priority in the submitted configuration order', async () => {
    const wrapper = mount(EndpointPool, {
      props: {
        endpoints: [endpoint(), { ...endpoint(), id: 'guard-2', name: 'Guard Two' }],
        probeResults: {},
        probingIds: [],
      },
      global: { stubs: { BaseDialog: DialogStub } },
    })

    expect(wrapper.get('[aria-label="admin.promptAudit.pool.moveUp"]').attributes()).toHaveProperty('disabled')
    await wrapper.findAll('[aria-label="admin.promptAudit.pool.moveDown"]')[0].trigger('click')

    const reordered = wrapper.emitted('update:endpoints')?.at(-1)?.[0] as PromptAuditEndpointDraft[]
    expect(reordered.map((item) => item.id)).toEqual(['guard-2', 'guard-1'])
  })

  it('supports group search, stale configured groups, nine scanners, and bounded worker inputs', async () => {
    const draft: PromptAuditDraft = {
      enabled: true, blocking_enabled: false, blocking_latest_turn_only: false, effective_mode: 'async_audit', strategy: 'priority',
      blocking_review_modules: { ...DEFAULT_BLOCKING_REVIEW_MODULES }, deep_review_modules: { ...DEFAULT_DEEP_REVIEW_MODULES },
      allow_receipt_ttl_seconds: 3600,
      worker_count: 4, queue_capacity: 100, scanners: SCANNER_CATALOG.map((item) => item.id), all_groups: false, group_ids: [1, 99], blocking_exempt_user_ids: [7],
      endpoints: [endpoint()], config_version: 1, updated_at: '', updated_by: 0, change_summary: '',
    }
    const wrapper = mount(PolicyPanel, {
      props: { draft, groups: [{ id: 1, name: 'Alpha', platform: 'openai', status: 'active' }, { id: 2, name: 'Beta', platform: 'claude', status: 'inactive' }] },
      global: { stubs: { OpenAIFastPolicyUserSelector: UserSelectorStub } },
    })
    expect(wrapper.text()).toContain('99')
    expect(wrapper.findAll('input[type="checkbox"]').filter((input) => SCANNER_CATALOG.some((scanner) => input.attributes('aria-label') === `admin.promptAudit.scanners.${scanner.id}`))).toHaveLength(9)
    await wrapper.get('[aria-label="admin.promptAudit.policy.searchGroups"]').setValue('Beta')
    expect(wrapper.text()).toContain('Beta')
    expect(wrapper.text()).not.toContain('Alpha')
    await wrapper.get('[aria-label="admin.promptAudit.policy.workerCount"]').setValue('6')
    let emitted = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(emitted.worker_count).toBe(6)
    await wrapper.get('[aria-label="admin.promptAudit.policy.allowReceiptTTL"]').setValue('7200')
    emitted = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(emitted.allow_receipt_ttl_seconds).toBe(7200)
    await wrapper.get('[data-test="blocking_review_modules-assistant"]').setValue(true)
    emitted = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(emitted.blocking_review_modules.assistant).toBe(true)
    expect(emitted.deep_review_modules.assistant).toBe(true)
    await wrapper.get('[data-test="pick-user"]').trigger('click')
    emitted = wrapper.emitted('update:draft')?.at(-1)?.[0] as PromptAuditDraft
    expect(emitted.blocking_exempt_user_ids).toEqual([42])
  })

  it('keeps identity fields separate, supports selection, and opens filter deletion from the toolbar', async () => {
    const event: PromptAuditEvent = {
      id: 1, job_id: 1, execution_mode: 'async_audit', decision: 'critical', risk_level: 'critical', action: 'Block', categories: ['pii', 'jailbreak'], matched_scanners: ['jailbreak'], scanner_scores: { pii: 1, jailbreak: 1 }, scanner_evidence: { pii: 'PII', jailbreak: 'Jailbreak' }, scanner_backend: 'qwen3guard-openai', scanner_version: '1', guard_endpoint_id: 'guard-1', guard_endpoint_name: 'Primary Guard', guard_model: 'guard-model', policy_id: 'priority', policy_version: 1, config_version: 1, chunk_total: 1, queue_delay_ms: 2500, input_limit: 500000, matched_chunk_index: 1, latency_ms: 10, issue_summaries: [], created_at: '2026-07-16T00:00:00Z', full_context_available: false,
      snapshot: { request_id: 'req-1', client_ip: '203.0.113.42', user_id: 1, username: 'alice', user_email: 'alice@example.test', api_key_id: 2, api_key_name: 'alice-key', group_id: 3, group_name: 'Alpha', provider: 'openai', endpoint: '/v1/chat/completions', protocol: 'openai_chat', model: 'gpt-test', prompt_hash: 'a'.repeat(64), redacted_preview: 'redacted preview', full_prompt: 'full prompt text', full_prompt_truncated: false, prompt_length: 10, message_count: 1, stage: 'http', blocking_exempt_at_request: true },
    }
    const wrapper = mount(EventWorkspace, {
      props: { events: [event], total: 1, page: 1, pageSize: 20, filters: emptyEventFilters(), selectedIds: [], loading: false, error: '' },
      global: { stubs: { Pagination: PaginationStub } },
    })
    expect(wrapper.text()).toContain('alice')
    expect(wrapper.text()).toContain('alice@example.test')
    expect(wrapper.text()).toContain('alice-key')
    expect(wrapper.text()).toContain('admin.promptAudit.decisions.critical · admin.promptAudit.riskLevels.critical')
    expect(wrapper.get('[data-test="event-1"]').text()).toContain('admin.promptAudit.scanners.jailbreak')
    expect(wrapper.get('[data-test="event-1"]').text()).not.toContain('admin.promptAudit.scanners.pii')
    expect(wrapper.text()).toContain('203.0.113.42')
    expect(wrapper.text()).toContain('2.50 s')
    expect(wrapper.get('[data-test="blocking-exempt-at-request"]').text()).toContain('admin.promptAudit.events.blockingExemptAtRequest')
    expect(wrapper.get('[data-test="audit-node"]').text()).toContain('Primary Guard')
    expect(wrapper.get('[data-test="audit-node"]').text()).toContain('guard-model')
    expect(wrapper.get('[data-test="audit-node"]').text()).toContain('guard-1')
    expect(wrapper.get('[data-test="filter-delete"]').attributes()).not.toHaveProperty('disabled')
    await wrapper.get('[data-test="cleanup-pass-events"]').trigger('click')
    expect(wrapper.emitted('cleanup-pass')).toHaveLength(1)
    await wrapper.get('[data-test="filter-delete"]').trigger('click')
    expect(wrapper.emitted('preview-delete')).toHaveLength(1)
    await wrapper.get('[aria-label="admin.promptAudit.events.selectEvent"]').setValue(true)
    expect(wrapper.emitted('selection')?.at(-1)?.[0]).toEqual([1])
    await wrapper.get('[aria-label="admin.promptAudit.events.filterByIp"]').trigger('click')
    expect((wrapper.emitted('search')?.at(-1)?.[0] as PromptEventFilters).client_ip).toBe('203.0.113.42')
    await wrapper.get('[aria-label="admin.promptAudit.events.filterByUserId"]').trigger('click')
    expect((wrapper.emitted('filters-change')?.at(-1)?.[0] as PromptEventFilters).user_id).toBe('1')
    expect((wrapper.emitted('search')?.at(-1)?.[0] as PromptEventFilters).user_id).toBe('1')
    const modeSelect = wrapper.findAllComponents(Select)[2]!
    modeSelect.vm.$emit('update:modelValue', 'async_deep')
    modeSelect.vm.$emit('change', 'async_deep')
    await nextTick()
    expect((wrapper.emitted('filters-change')?.at(-1)?.[0] as PromptEventFilters).execution_mode).toBe('async_deep')
    await wrapper.get('[data-test="analyze-user"]').trigger('click')
    expect(wrapper.emitted('analyze')?.at(-1)?.[0]).toBe(1)
  })

  it('shows failed audit events with a safe reason and error code', async () => {
    const event: PromptAuditEvent = {
      id: 8, job_id: 9, execution_mode: 'blocking', decision: 'failed', risk_level: 'unknown', action: 'Error',
      error_code: 'prompt_guard_unavailable', error_message: 'Prompt Guard endpoint timed out',
      categories: [], matched_scanners: [], scanner_scores: {}, scanner_evidence: {},
      scanner_backend: 'qwen3guard-openai', scanner_version: 'guard-model', guard_endpoint_id: 'guard-1',
      guard_endpoint_name: 'Primary Guard', guard_model: 'guard-model', policy_id: 'priority', policy_version: 0,
      config_version: 7, chunk_total: 3, queue_delay_ms: 0, input_limit: 200000, matched_chunk_index: null,
      latency_ms: 15000, issue_summaries: [], created_at: '2026-08-30T15:45:42Z', full_context_available: false,
      snapshot: {
        request_id: 'failed-request', client_ip: '203.0.113.42', user_id: 7, username: 'alice',
        user_email: 'alice@example.test', api_key_id: 8, api_key_name: 'alice-key', group_id: 5,
        group_name: 'Primary', provider: 'openai', endpoint: '/v1/responses', protocol: 'openai_responses',
        model: 'gpt-test', prompt_hash: 'f'.repeat(64), redacted_preview: 'redacted failure preview',
        full_prompt: 'FULL_PROMPT_MUST_NOT_RENDER', full_prompt_truncated: true, prompt_length: 20,
        message_count: 1, stage: 'http',
      },
    }
    const workspace = mount(EventWorkspace, {
      props: { events: [event], total: 1, page: 1, pageSize: 20, filters: emptyEventFilters(), selectedIds: [], loading: false, error: '' },
      global: { stubs: { Pagination: PaginationStub } },
    })
    expect(workspace.get('[data-test="event-8"]').text()).toContain('Prompt Guard endpoint timed out')
    expect(workspace.get('[data-test="event-8"]').text()).toContain('prompt_guard_unavailable')
  })

  it('resolves delete range presets to an epoch start and a cutoff end', () => {
    const now = Date.parse('2026-07-17T12:00:00.000Z')
    const sevenDays = resolveDeleteRangeFilters(emptyEventFilters(), '7d', now)
    expect(sevenDays.start_at).toBe('1970-01-01T00:00:00.000Z')
    expect(sevenDays.end_at).toBe('2026-07-10T12:00:00.000Z')
    const all = resolveDeleteRangeFilters(emptyEventFilters(), 'all', now)
    expect(all.start_at).toBe('1970-01-01T00:00:00.000Z')
    expect(all.end_at).toBe('2026-07-17T12:00:00.000Z')
    const customSource = { ...emptyEventFilters(), start_at: '2026-07-01T00:00', end_at: '2026-07-02T00:00' }
    expect(resolveDeleteRangeFilters(customSource, 'custom', now)).toEqual(customSource)
  })

  it('drives filter deletion through presets, custom validation, preview, and confirm', async () => {
    const wrapper = mount(FilterDeleteDialog, {
      props: { show: true, initialFilters: emptyEventFilters(), preview: null, previewing: false, deleting: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get<HTMLInputElement>('[data-test="range-preset-7d"]').element.checked).toBe(true)
    expect(wrapper.find('[data-test="custom-range"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="delete-preview-empty"]').exists()).toBeTruthy()
    // A valid preset is enough: confirm is armed immediately (one-click flow)
    // and needs no disabled-reason hint.
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).not.toHaveProperty('disabled')
    expect(wrapper.find('[data-test="confirm-disabled-reason"]').exists()).toBe(false)
    await wrapper.get('[data-test="confirm-filter-delete"]').trigger('click')
    const directConfirm = wrapper.emitted('confirm')?.at(-1)?.[0] as PromptEventFilters
    expect(directConfirm.start_at).toBe('1970-01-01T00:00:00.000Z')
    expect(Date.now() - new Date(directConfirm.end_at).getTime()).toBeGreaterThanOrEqual(7 * 24 * 60 * 60 * 1000)

    await wrapper.get('[data-test="range-preset-30d"]').setValue()
    expect(wrapper.emitted('criteria-change')?.length).toBeGreaterThan(0)
    const riskSelect = wrapper.findAllComponents(Select)[1]!
    riskSelect.vm.$emit('update:modelValue', 'high')
    riskSelect.vm.$emit('change', 'high')
    await nextTick()
    await wrapper.get('[data-test="run-delete-preview"]').trigger('click')
    const presetPreview = wrapper.emitted('preview')?.at(-1)?.[0] as PromptEventFilters
    expect(presetPreview.risk_level).toBe('high')
    expect(presetPreview.start_at).toBe('1970-01-01T00:00:00.000Z')
    expect(Date.now() - new Date(presetPreview.end_at).getTime()).toBeGreaterThanOrEqual(30 * 24 * 60 * 60 * 1000)

    await wrapper.get('[data-test="range-preset-custom"]').setValue()
    expect(wrapper.find('[data-test="custom-range"]').exists()).toBe(true)
    expect(wrapper.get('[data-test="run-delete-preview"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('[data-test="confirm-disabled-reason"]').text()).toBe('admin.promptAudit.events.filterDeleteConfirmInvalidRange')
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes('title')).toBe('admin.promptAudit.events.filterDeleteConfirmInvalidRange')
    await wrapper.get('[data-test="custom-range"] [aria-label="admin.promptAudit.events.startAt"]').setValue('2026-07-01T00:00')
    await wrapper.get('[data-test="custom-range"] [aria-label="admin.promptAudit.events.endAt"]').setValue('2026-07-02T00:00')
    expect(wrapper.get('[data-test="run-delete-preview"]').attributes()).not.toHaveProperty('disabled')
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).not.toHaveProperty('disabled')
    expect(wrapper.find('[data-test="confirm-disabled-reason"]').exists()).toBe(false)
    await wrapper.get('[data-test="run-delete-preview"]').trigger('click')
    const customPreview = wrapper.emitted('preview')?.at(-1)?.[0] as PromptEventFilters
    expect(customPreview.start_at).toBe('2026-07-01T00:00')
    expect(customPreview.end_at).toBe('2026-07-02T00:00')

    await wrapper.setProps({
      preview: { matched_count: 3, matched_context_count: 2, estimated_reclaimable_bytes: 4096, filter_summary: {}, snapshot_max_id: 9, filter_hash: 'b'.repeat(64), confirmation_token: 'tok', expires_at: '2026-07-16T00:05:00Z' },
    })
    expect(wrapper.get('[data-test="delete-preview-result"]').text()).toContain('admin.promptAudit.events.filterDeleteCount')
    expect(wrapper.find('[data-test="confirm-disabled-reason"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).not.toHaveProperty('disabled')
    await wrapper.get('[data-test="confirm-filter-delete"]').trigger('click')
    const confirmed = wrapper.emitted('confirm')?.at(-1)?.[0] as PromptEventFilters
    expect(confirmed.start_at).toBe('2026-07-01T00:00')
    expect(confirmed.end_at).toBe('2026-07-02T00:00')
  })

  it('explains that a zero-match preview leaves nothing to delete', async () => {
    const wrapper = mount(FilterDeleteDialog, {
      props: {
        show: true,
        initialFilters: emptyEventFilters(),
        preview: { matched_count: 0, matched_context_count: 0, estimated_reclaimable_bytes: 0, filter_summary: {}, snapshot_max_id: 0, filter_hash: 'c'.repeat(64), confirmation_token: 'tok', expires_at: '2026-07-16T00:05:00Z' },
        previewing: false,
        deleting: false,
      },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('[data-test="confirm-disabled-reason"]').text()).toBe('admin.promptAudit.events.filterDeleteConfirmNoMatches')
    await wrapper.setProps({ previewing: true })
    expect(wrapper.find('[data-test="confirm-disabled-reason"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="confirm-filter-delete"]').attributes()).toHaveProperty('disabled')
  })

  it('inherits an explicit list-filter range as the custom preset', async () => {
    const initialFilters = { ...emptyEventFilters(), start_at: '2026-07-01T00:00', end_at: '2026-07-02T00:00', decision: 'critical' }
    const wrapper = mount(FilterDeleteDialog, {
      props: { show: true, initialFilters, preview: null, previewing: false, deleting: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get<HTMLInputElement>('[data-test="range-preset-custom"]').element.checked).toBe(true)
    expect(wrapper.get<HTMLInputElement>('[data-test="custom-range"] [aria-label="admin.promptAudit.events.startAt"]').element.value).toBe('2026-07-01T00:00')
    expect(wrapper.findAllComponents(Select)[0]!.props('modelValue')).toBe('critical')
    expect(wrapper.get('[data-test="run-delete-preview"]').attributes()).not.toHaveProperty('disabled')
  })

  it('keeps normal-event cleanup fixed to Pass and disabled until preview', async () => {
    const wrapper = mount(PassEventCleanupDialog, {
      props: { show: true, preview: null, previewing: false, deleting: false },
      global: { stubs: { BaseDialog: DialogStub, OpenAIFastPolicyUserSelector: UserSelectorStub } },
    })
    expect(wrapper.get('[data-test="confirm-pass-cleanup"]').attributes()).toHaveProperty('disabled')
    await wrapper.get('[data-test="preview-pass-cleanup"]').trigger('click')
    const filters = wrapper.emitted('preview')?.at(-1)?.[0] as PromptEventFilters
    expect(filters.decision).toBe('pass')
    expect(filters.start_at).toBe('1970-01-01T00:00:00.000Z')

    await wrapper.setProps({
      preview: { matched_count: 5, matched_context_count: 4, estimated_reclaimable_bytes: 5 * 1024 ** 3, filter_summary: {}, snapshot_max_id: 12, filter_hash: 'd'.repeat(64), confirmation_token: 'tok', expires_at: '2026-07-16T00:05:00Z' },
    })
    expect(wrapper.get('[data-test="pass-cleanup-preview"]').text()).toContain('5.00 GB')
    expect(wrapper.get('[data-test="confirm-pass-cleanup"]').attributes()).not.toHaveProperty('disabled')
    await wrapper.get('[data-test="confirm-pass-cleanup"]').trigger('click')
    expect(wrapper.emitted('confirm')).toHaveLength(1)
  })

  it('shows the full unredacted prompt and structured guard return on the risks tab', async () => {
    const event: PromptAuditEvent = {
      id: 1, job_id: 1, execution_mode: 'blocking', decision: 'critical', risk_level: 'critical', action: 'Block',
      categories: ['pii', 'sexual_content_or_sexual_acts'], matched_scanners: ['sexual_content_or_sexual_acts'],
      scanner_scores: { pii: 1, sexual_content_or_sexual_acts: 1 },
      scanner_evidence: { pii: 'PII', sexual_content_or_sexual_acts: 'Sexual Content or Sexual Acts' },
      scanner_backend: 'qwen3guard-openai', scanner_version: 'qwen3guard', guard_endpoint_id: 'guard-1', guard_endpoint_name: 'Primary Guard', guard_model: 'guard-model',
      policy_id: 'priority', policy_version: 1, config_version: 1, chunk_total: 4, queue_delay_ms: 0, input_limit: 100000, matched_chunk_index: 3, latency_ms: 12,
      issue_summaries: [{
        category: 'sexual_content_or_sexual_acts', scanner_id: 'sexual_content_or_sexual_acts',
        title: '性内容或性行为', description: 'Sexual content or sexual acts', severity: 'critical',
        severity_label: '严重', action: 'Block', action_label: '阻止',
        code: 'prompt_audit_sexual_content_or_sexual_acts', score: 1,
        evidence: 'Sexual Content or Sexual Acts', evidence_hash: 'abc',
      }],
      created_at: '2026-07-16T00:00:00Z',
      full_context_available: true,
      snapshot: {
        request_id: 'req-1', client_ip: '203.0.113.42', user_id: 1, username: 'alice', user_email: 'alice@example.test',
        api_key_id: 2, api_key_name: 'alice-key', group_id: 3, group_name: 'Alpha', provider: 'openai',
        endpoint: '/v1/chat/completions', protocol: 'openai_chat', model: 'gpt-test',
        prompt_hash: 'a'.repeat(64), redacted_preview: 'redacted prompt body', full_prompt: 'complete unmasked prompt body', full_prompt_truncated: false, prompt_length: 20,
        message_count: 1, stage: 'http',
      },
    }
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, event, loading: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    const panel = wrapper.get('[data-test="event-detail-tab-panel"]')
    expect(panel.classes()).toContain('h-[min(62vh,36rem)]')
    expect(panel.classes()).toContain('overflow-y-auto')

    const riskTab = wrapper.findAll('[role="tab"]').find((tab) => tab.text().includes('admin.promptAudit.events.tabs.risks'))
    expect(riskTab).toBeTruthy()
    await riskTab!.trigger('click')
    expect(wrapper.get('[data-test="event-detail-tab-panel"]').classes()).toContain('h-[min(62vh,36rem)]')
    expect(wrapper.get('[data-test="risk-prompt-preview"]').text()).toContain('complete unmasked prompt body')
    expect(wrapper.get('[data-test="risk-prompt-preview"]').text()).not.toContain('redacted prompt body')
    expect(wrapper.get('[data-test="risk-prompt-full"]').classes()).toContain('overflow-auto')
    expect(wrapper.get('[data-test="risk-guard-return"]').text()).toContain('"decision": "admin.promptAudit.decisions.critical"')
    expect(wrapper.get('[data-test="risk-guard-return"]').text()).toContain('admin.promptAudit.scanners.sexual_content_or_sexual_acts')
    expect(wrapper.get('[data-test="risk-guard-return"]').text()).not.toContain('admin.promptAudit.scanners.pii')
    expect(wrapper.get('[data-test="risk-issue"]').text()).toContain('admin.promptAudit.scanners.sexual_content_or_sexual_acts')
    expect(wrapper.text()).toContain('Primary Guard')
    expect(wrapper.text()).toContain('guard-model')

    const originalCreateObjectURL = window.URL.createObjectURL
    const originalRevokeObjectURL = window.URL.revokeObjectURL
    const createObjectURL = vi.fn(() => 'blob:prompt-audit')
    const revokeObjectURL = vi.fn()
    window.URL.createObjectURL = createObjectURL
    window.URL.revokeObjectURL = revokeObjectURL
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
    try {
      const contextBlob = new Blob(['{"segments":[]}'], { type: 'application/json' })
      downloadEventContext.mockResolvedValue(contextBlob)
      await wrapper.get('[data-test="download-context"]').trigger('click')
      await Promise.resolve()
      expect(createObjectURL).toHaveBeenCalledOnce()
      expect(downloadEventContext).toHaveBeenCalledWith(1)
      expect(createObjectURL).toHaveBeenCalledWith(contextBlob)
      expect(click).toHaveBeenCalledOnce()
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:prompt-audit')
    } finally {
      window.URL.createObjectURL = originalCreateObjectURL
      window.URL.revokeObjectURL = originalRevokeObjectURL
    }
  })

  it('falls back to the redacted preview for events stored before full prompts were kept', async () => {
    const event: PromptAuditEvent = {
      id: 2, job_id: 2, execution_mode: 'async_audit', decision: 'flag', risk_level: 'medium', action: 'Warn',
      categories: ['pii'], matched_scanners: ['pii'], scanner_scores: {}, scanner_evidence: {},
      scanner_backend: 'qwen3guard-openai', scanner_version: 'legacy-guard-model', guard_endpoint_id: 'legacy-guard-node',
      policy_id: 'priority', policy_version: 1, config_version: 1, chunk_total: 1, latency_ms: 5,
      issue_summaries: [], created_at: '2026-07-16T00:00:00Z',
      full_context_available: false,
      snapshot: {
        request_id: 'req-2', client_ip: '', user_id: 1, username: 'bob', user_email: '', api_key_id: 2,
        api_key_name: 'bob-key', group_id: 3, group_name: 'Alpha', provider: 'openai',
        endpoint: '/v1/chat/completions', protocol: 'openai_chat', model: 'gpt-test',
        prompt_hash: 'b'.repeat(64), redacted_preview: 'legacy redacted preview', full_prompt: '', full_prompt_truncated: true, prompt_length: 20,
        message_count: 1, stage: 'http',
      },
    }
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, event, loading: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    const riskTab = wrapper.findAll('[role="tab"]').find((tab) => tab.text().includes('admin.promptAudit.events.tabs.risks'))
    await riskTab!.trigger('click')
    expect(wrapper.get('[data-test="risk-prompt-full"]').text()).toContain('legacy redacted preview')
    expect(wrapper.get('[data-test="prompt-truncated-warning"]').text()).toContain('admin.promptAudit.events.promptTruncatedWarning')
    expect(wrapper.get('[data-test="download-context"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.text()).toContain('legacy-guard-node')
    expect(wrapper.text()).toContain('legacy-guard-model')
  })

  it('labels an unselected Pass as a lightweight event instead of a truncated failure', () => {
    const event: PromptAuditEvent = {
      id: 3, job_id: 3, execution_mode: 'blocking', decision: 'pass', risk_level: 'low', action: 'Allow',
      categories: [], matched_scanners: [], scanner_scores: {}, scanner_evidence: {},
      scanner_backend: 'qwen3guard-openai', scanner_version: '1', guard_endpoint_id: 'guard-1',
      policy_id: 'priority', policy_version: 1, config_version: 1, chunk_total: 1, latency_ms: 5,
      issue_summaries: [], created_at: '2026-07-16T00:00:00Z', full_context_available: false,
      snapshot: {
        request_id: 'req-3', client_ip: '', user_id: 1, username: 'carol', user_email: '', api_key_id: 2,
        api_key_name: 'carol-key', group_id: 3, group_name: 'Alpha', provider: 'openai',
        endpoint: '/v1/chat/completions', protocol: 'openai_chat', model: 'gpt-test',
        prompt_hash: 'c'.repeat(64), redacted_preview: 'lightweight redacted preview', full_prompt: '',
        full_prompt_truncated: true, prompt_length: 28, message_count: 1, stage: 'http',
      },
    }
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, event, loading: false },
      global: { stubs: { BaseDialog: DialogStub } },
    })

    expect(wrapper.get('[data-test="summary-prompt-full"]').text()).toContain('lightweight redacted preview')
    expect(wrapper.get('[data-test="lightweight-pass-notice"]').text()).toContain('admin.promptAudit.events.passEvidenceNotRetained')
    expect(wrapper.find('[data-test="prompt-truncated-warning"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('admin.promptAudit.events.contentLightweight')
  })
})
