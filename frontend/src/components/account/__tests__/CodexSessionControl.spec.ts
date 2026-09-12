import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import CodexSessionControl from '../CodexSessionControl.vue'
import type { Account } from '@/types'

const { getConfig, saveConfig } = vi.hoisted(() => ({ getConfig: vi.fn(), saveConfig: vi.fn() }))
vi.mock('@/api/admin', () => ({ adminAPI: { accounts: { getCodexSession: getConfig, saveCodexSession: saveConfig } } }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

const initial = { enabled: false, session_id: '', supported: true, effective_session_id: 'original-session' }
const account = { id: 5, platform: 'openai', type: 'oauth', extra: { codex_fingerprint_mode: 'session' } } as Account

function render() {
  return mount(CodexSessionControl, { props: { account, busy: false }, global: { stubs: { Icon: true } } })
}

describe('CodexSessionControl', () => {
  beforeEach(() => {
    getConfig.mockReset().mockResolvedValue({ ...initial })
    saveConfig.mockReset()
  })

  it('生成草稿只通知测试，保存完成前保持锁定，保存后清除草稿', async () => {
    const wrapper = render()
    await flushPromises()
    await wrapper.get('[data-testid="codex-session-enabled"]').setValue(true)
    const draft = wrapper.emitted('draft')!.at(-1)![0] as { enabled: boolean; session_id: string }
    expect(draft.enabled).toBe(true)
    expect(draft.session_id).toMatch(/^[0-9a-f-]{36}$/)
    expect(saveConfig).not.toHaveBeenCalled()
    expect((wrapper.get('[data-testid="codex-session-id"]').element as HTMLInputElement).value).toBe(draft.session_id)

    let finish!: (value: unknown) => void
    saveConfig.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    await wrapper.get('[data-testid="codex-session-save"]').trigger('click')
    expect(saveConfig).toHaveBeenCalledWith(5, { ...draft, account_turn: expect.objectContaining({ enabled: false }) })
    expect(wrapper.emitted('pending')!.at(-1)).toEqual([true])
    expect(wrapper.get('[data-testid="codex-session-random"]').attributes('disabled')).toBeDefined()
    finish({ ...initial, ...draft, effective_session_id: draft.session_id })
    await flushPromises()
    expect(wrapper.emitted('draft')!.at(-1)).toEqual([null])
    expect(wrapper.emitted('saved')).toHaveLength(1)
    expect(wrapper.emitted('pending')!.at(-1)).toEqual([false])
    expect(wrapper.text()).toContain('admin.accounts.openai.sessionOverrideReconnectHint')
    wrapper.unmount()
  })

  it('关闭时忽略迟到的保存响应，重新打开重新读取已保存配置', async () => {
    let finish!: (value: unknown) => void
    saveConfig.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const wrapper = render()
    await flushPromises()
    await wrapper.get('[data-testid="codex-session-enabled"]').setValue(true)
    await wrapper.get('[data-testid="codex-session-save"]').trigger('click')
    wrapper.unmount()
    expect(wrapper.emitted('pending')!.at(-1)).toEqual([false])
    finish({ ...initial, enabled: true, session_id: 'saved-after-close' })
    await flushPromises()
    expect(wrapper.emitted('saved')).toBeUndefined()

    getConfig.mockResolvedValue({ ...initial, enabled: true, session_id: 'saved-after-close' })
    const reopened = render()
    await flushPromises()
    expect(getConfig).toHaveBeenCalledTimes(2)
    expect((reopened.get('[data-testid="codex-session-id"]').element as HTMLInputElement).value).toBe('saved-after-close')
    reopened.unmount()
  })

  it('切换账号不会显示旧账号迟到的配置', async () => {
    let finish!: (value: unknown) => void
    getConfig.mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    const wrapper = render()
    await wrapper.setProps({ account: { ...account, id: 12 } })
    await flushPromises()
    finish({ ...initial, enabled: true, session_id: 'old-account-session' })
    await flushPromises()
    expect(wrapper.find('[data-testid="codex-session-id"]').exists()).toBe(false)
    expect(wrapper.emitted('pending')!.at(-1)).toEqual([false])
    wrapper.unmount()
  })

  it('成功捕获后一次保存会话与回合，重新打开恢复配置', async () => {
    const wrapper = render()
    await flushPromises()
    await wrapper.get('[data-testid="codex-session-enabled"]').setValue(true)
    await wrapper.get('[data-testid="codex-test-state-enabled"]').setValue(true)
    const draft = wrapper.emitted('turn-draft')!.at(-1)![0] as { turn_id: string }
    expect(wrapper.get('[data-testid="codex-session-save"]').attributes('disabled')).toBeDefined()
    await wrapper.setProps({ captured: { turn_id: draft.turn_id, turn_state: 'chosen-state', identity: 'chosen-identity' } })
    expect(wrapper.get('[data-testid="codex-session-save"]').attributes('disabled')).toBeUndefined()
    saveConfig.mockImplementation((_id, value) => Promise.resolve({ ...initial, ...value, account_turn: { ...value.account_turn, revision: 'saved-v1', updated_at: '2026-09-12T12:00:00Z' } }))
    await wrapper.get('[data-testid="codex-session-save"]').trigger('click')
    await flushPromises()
    expect(saveConfig).toHaveBeenCalledWith(5, expect.objectContaining({ enabled: true, account_turn: expect.objectContaining({ turn_id: draft.turn_id, turn_state: 'chosen-state', identity: 'chosen-identity' }) }))
    const saved = await saveConfig.mock.results[0].value
    wrapper.unmount()
    getConfig.mockResolvedValue(saved)
    const reopened = render()
    await flushPromises()
    expect(reopened.get<HTMLInputElement>('[data-testid="codex-test-turn-id"]').element.value).toBe(draft.turn_id)
    expect(reopened.emitted('turn-draft')!.at(-1)![0]).toMatchObject({ turn_id: draft.turn_id, turn_state: 'chosen-state' })
    reopened.unmount()
  })

  it('更换会话清空状态，迟到的旧回合响应不会覆盖新草稿', async () => {
    getConfig.mockResolvedValue({ ...initial, enabled: true, session_id: 'session', account_turn: { enabled: true, turn_id: 'old-turn', turn_state: 'old-state', identity: 'old-identity', revision: 'v1', updated_at: '' } })
    const wrapper = render()
    await flushPromises()
    await wrapper.get('[data-testid="codex-session-random"]').trigger('click')
    expect(wrapper.emitted('turn-draft')!.at(-1)![0]).toMatchObject({ turn_state: '', identity: '' })
    await wrapper.get('[data-testid="codex-test-turn-id-random"]').trigger('click')
    await wrapper.setProps({ captured: { turn_id: 'old-turn', turn_state: 'late-state', identity: 'old-identity' } })
    expect(wrapper.get('[data-testid="codex-session-save"]').attributes('disabled')).toBeDefined()
    expect(saveConfig).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('保存冲突保留草稿并提示重新加载，禁用可以直接保存', async () => {
    getConfig.mockResolvedValue({ ...initial, account_turn: { enabled: true, turn_id: 'turn', turn_state: 'state', identity: 'identity', revision: 'v1', updated_at: '' } })
    const wrapper = render()
    await flushPromises()
    await wrapper.get('[data-testid="codex-test-state-enabled"]').setValue(false)
    saveConfig.mockRejectedValue({ response: { status: 409 } })
    await wrapper.get('[data-testid="codex-session-save"]').trigger('click')
    await flushPromises()
    expect(saveConfig).toHaveBeenCalledWith(5, expect.objectContaining({ account_turn: expect.objectContaining({ enabled: false, revision: 'v1' }) }))
    expect(wrapper.get('[role="alert"]').text()).toContain('sessionOverrideSaveFailed')
    expect(wrapper.emitted('saved')).toBeUndefined()
    wrapper.unmount()
  })
})
