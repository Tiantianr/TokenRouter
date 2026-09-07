import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import VersionBadge from '../VersionBadge.vue'

const mocks = vi.hoisted(() => ({
  app: {
    versionLoading: false,
    currentVersion: '0.1.279',
    latestVersion: '0.1.280',
    hasUpdate: true,
    releaseInfo: null,
    buildType: 'image',
    fetchVersion: vi.fn(),
    clearVersionCache: vi.fn()
  },
  update: vi.fn(),
  rollback: vi.fn()
}))

vi.mock('@/stores', () => ({
  useAuthStore: () => ({ isAdmin: true }),
  useAppStore: () => mocks.app
}))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@/api/admin/system', () => ({
  performUpdate: mocks.update,
  rollback: mocks.rollback,
  restartService: vi.fn(),
  getRollbackVersions: vi.fn()
}))
vi.mock('@/composables/useClipboard', () => ({
  useClipboard: () => ({ copied: false, copyToClipboard: vi.fn() })
}))

describe('镜像版本更新入口', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.app.buildType = 'image'
    mocks.app.hasUpdate = true
  })

  it.each([true, false])('有无更新均不显示二进制更新或回退按钮：%s', async (hasUpdate) => {
    mocks.app.hasUpdate = hasUpdate
    const wrapper = mount(VersionBadge, { global: { stubs: { Icon: true } } })
    await wrapper.get('button').trigger('click')
    expect(wrapper.text()).toContain('version.imageModeHint')
    expect(wrapper.text()).toContain(`ghcr.io/tiantianr/tokenrouter:${hasUpdate ? '0.1.280' : '0.1.279'}`)
    expect(wrapper.get('a').attributes('href')).toBe('https://github.com/Tiantianr/TokenRouter/releases')
    expect(wrapper.findAll('button').some((button) => /version\.(updateNow|rollback)$/.test(button.text()))).toBe(false)
    expect(mocks.update).not.toHaveBeenCalled()
    expect(mocks.rollback).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('原二进制构建仍保留既有更新入口', async () => {
    mocks.app.buildType = 'release'
    const wrapper = mount(VersionBadge, { global: { stubs: { Icon: true } } })
    await wrapper.get('button').trigger('click')
    expect(wrapper.text()).not.toContain('version.imageModeHint')
    expect(wrapper.text()).toContain('version.updateNow')
    wrapper.unmount()
  })
})
