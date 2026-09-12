import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import CodexTestStateControl from '../CodexTestStateControl.vue'
import type { CodexAccountTurnConfiguration } from '@/api/admin/accounts'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

describe('CodexTestStateControl', () => {
  it('随机回合和禁用都清除旧状态，保留保存时需要的版本', async () => {
    const value: CodexAccountTurnConfiguration = { enabled: true, turn_id: 'old-turn', turn_state: 'state', identity: 'identity', revision: 'v1', updated_at: '' }
    const wrapper = mount(CodexTestStateControl, { props: { value, busy: false }, global: { stubs: { Icon: true } } })
    await wrapper.get('[data-testid="codex-test-turn-id-random"]').trigger('click')
    const random = wrapper.emitted('change')!.at(-1)![0] as CodexAccountTurnConfiguration
    expect(random.turn_id).toMatch(/^[0-9a-f-]{36}$/)
    expect(random).toMatchObject({ enabled: true, turn_state: '', identity: '', revision: 'v1' })
    await wrapper.get('[data-testid="codex-test-state-enabled"]').setValue(false)
    expect(wrapper.emitted('change')!.at(-1)![0]).toMatchObject({ enabled: false, turn_state: '', revision: 'v1' })
  })
})
