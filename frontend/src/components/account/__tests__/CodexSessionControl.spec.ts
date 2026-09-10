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
    expect(saveConfig).toHaveBeenCalledWith(5, draft)
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
})
