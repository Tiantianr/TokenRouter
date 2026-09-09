import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import SessionWorkspace from '../components/SessionWorkspace.vue'

const { listSessions, listSessionEvents } = vi.hoisted(() => ({ listSessions: vi.fn(), listSessionEvents: vi.fn() }))
vi.mock('../api', () => ({ listSessions, listSessionEvents }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

// 从会话浏览到事件证据操作的真实交互，避免入口存在但无法进入详情。
describe('Session evidence workspace', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    listSessions.mockResolvedValue({ items: [{ id: 12, user_id: 7, session_key: 'a'.repeat(64), session_source: 'header:session-id', last_seen_at: '2026-09-09T00:00:00Z', event_count: 2, risk_count: 1, evidence_count: 1 }], total: 1 })
    listSessionEvents.mockResolvedValue({ items: [{ id: 42, decision: 'critical', created_at: '2026-09-09T00:00:00Z', snapshot: { model: 'test-model' }, full_context_available: true }], total: 1 })
  })
  it('opens the selected session and emits the event for evidence detail', async () => {
    const wrapper = mount(SessionWorkspace)
    await flushPromises()
    await wrapper.get('[data-test="open-session"]').trigger('click')
    await flushPromises()
    expect(listSessionEvents).toHaveBeenCalledWith(12, 1)
    expect(wrapper.text()).toContain('admin.promptAudit.sessions.available')
    await wrapper.get('[data-test="view-evidence"]').trigger('click')
    expect(wrapper.emitted('view')).toEqual([[42]])
    await wrapper.get('[data-test="manage-session"]').trigger('click')
    expect(wrapper.emitted('manage')).toEqual([[12]])
  })
  it('shows a recoverable failure instead of stale evidence from the previous request', async () => {
    const wrapper = mount(SessionWorkspace)
    await flushPromises()
    listSessionEvents.mockRejectedValueOnce(new Error('unavailable'))
    await wrapper.get('[data-test="open-session"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="view-evidence"]').exists()).toBe(false)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('[data-test="open-session"]').exists()).toBe(true)
  })
})
