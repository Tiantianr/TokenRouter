import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import type { SubscriptionPlan } from '@/types/payment'
import type { UserSubscription } from '@/types'

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string) => key,
  }),
}))

vi.mock('@/composables/useBalanceDisplay', () => ({
  useBalanceDisplay: () => ({
    formatBalanceAmount: (value: number | null | undefined) => String(value ?? ''),
  }),
}))

import SubscriptionPlanCard from '../SubscriptionPlanCard.vue'

// 统一构造套餐卡片，便于覆盖平台和币种的组合展示。
const mountPlanCard = (
  groupPlatform: string,
  currency = '',
  originalPrice?: number,
  overrides: Partial<SubscriptionPlan> = {},
) =>
  mount(SubscriptionPlanCard, {
    props: {
      plan: {
        id: 1,
        group_id: 10,
        group_platform: groupPlatform,
        name: 'Pro',
        description: '',
        price: 10,
        original_price: originalPrice,
        currency,
        validity_days: 30,
        validity_unit: 'day',
        features: [],
        for_sale: true,
        sort_order: 1,
        supported_model_scopes: ['claude', 'gemini_text', 'gemini_image'],
        ...overrides,
      },
    },
  })

describe('SubscriptionPlanCard', () => {
  it('恢复平台标签与浅色倍率额度区，不为缺失倍率编造 x1', () => {
    const wrapper = mountPlanCard('openai')
    expect(wrapper.text()).toContain('OpenAI')
    expect(wrapper.get('[data-testid="plan-metrics"]').classes()).toContain('bg-accent-50')
    expect(wrapper.classes()).toContain('rounded-[16px]')
    expect(wrapper.text()).toContain('payment.planCard.rateByGroup')
    expect(wrapper.text()).not.toContain('x1')
  })

  it('完整分组倍率显示数值或范围，缺失项回退按分组', () => {
    expect(mountPlanCard('openai', '', undefined, { group_ids: [1], group_rate_multipliers: { 1: 1 } }).text()).toContain('x1')
    expect(mountPlanCard('openai', '', undefined, { group_ids: [1, 2], group_rate_multipliers: { 1: 0, 2: 2 } }).text()).toContain('x0 ~ x2')
    expect(mountPlanCard('openai', '', undefined, { group_ids: [1, 2], group_rate_multipliers: { 1: 1 } }).text()).toContain('payment.planCard.rateByGroup')
  })

  it('通过按钮选择套餐并展示父级控制的选中状态', async () => {
    const wrapper = mountPlanCard('openai')
    expect(wrapper.get('button').attributes('aria-pressed')).toBe('false')
    await wrapper.get('button').trigger('click')
    expect(wrapper.emitted('select')).toEqual([[wrapper.props('plan')]])
    await wrapper.setProps({ selected: true })
    expect(wrapper.get('button').attributes('aria-pressed')).toBe('true')
    expect(wrapper.classes()).toContain('border-blue-600')
    expect(wrapper.classes()).toContain('lg:-translate-y-2')
    expect(wrapper.get('[data-testid="plan-selected-badge"]').text()).toBe('payment.selectedPlan')
    expect(wrapper.text()).not.toContain('popular')
  })

  it('点击卡片标题也能选择，内部按钮不会重复触发选择', async () => {
    const wrapper = mountPlanCard('openai')
    await wrapper.get('h3').trigger('click')
    await wrapper.get('button').trigger('click')
    expect(wrapper.emitted('select')).toHaveLength(2)
  })

  it('保留本工程正数额度和按套餐 ID 判断续费的语义', async () => {
    const wrapper = mountPlanCard('openai', '', undefined, {
      daily_limit_usd: 0,
      weekly_limit_usd: 2000,
      monthly_limit_usd: -1,
    })
    expect(wrapper.text()).toContain('2000')
    expect(wrapper.text()).not.toContain('payment.planCard.dailyLimit')
    expect(wrapper.text()).not.toContain('payment.planCard.monthlyLimit')
    await wrapper.setProps({ activeSubscriptions: [{ plan_id: 1, status: 'active' }] as UserSubscription[] })
    expect(wrapper.get('button').text()).toBe('payment.renewNow')
  })

  it('does not show Antigravity model scopes for OpenAI plans', () => {
    const text = mountPlanCard('openai').text()

    expect(text).not.toContain('Claude')
    expect(text).not.toContain('Gemini')
    expect(text).not.toContain('Imagen')
  })

  it('shows model scopes for Antigravity plans', () => {
    const text = mountPlanCard('antigravity').text()

    expect(text).toContain('Claude')
    expect(text).toContain('Gemini')
    expect(text).toContain('Imagen')
  })

  // 卡片必须同时兼容历史单数单位和管理端曾写入的复数单位。
  it('renders plural validity units instead of mislabeled days', () => {
    expect(mountPlanCard('openai', '', undefined, { validity_days: 1, validity_unit: 'months' }).text()).toContain('/ payment.perMonth')
    expect(mountPlanCard('openai', '', undefined, { validity_days: 3, validity_unit: 'months' }).text()).toContain('/ 3payment.months')
    expect(mountPlanCard('openai', '', undefined, { validity_days: 2, validity_unit: 'weeks' }).text()).toContain('/ 2payment.weeks')
    expect(mountPlanCard('openai', '', undefined, { validity_days: 30, validity_unit: 'day' }).text()).toContain('/ 30payment.days')
  })

  it('uses the configured currency symbol on current and original prices', () => {
    const text = mountPlanCard('openai', 'NZD', 20).text()

    expect(text).toContain('NZ$10NZD')
    expect(text).toContain('NZ$20NZD')
    expect(mountPlanCard('openai', 'CNY', 20).text()).toContain('¥10CNY')
    expect(mountPlanCard('openai').text()).toContain('$10')
  })

  it.each([
    ['长中文', '企业全球加速专业订阅套餐（含高级模型与优先支持）'],
    ['长英文', 'Enterprise Global Acceleration Subscription with Priority Support'],
    ['无空格长词', 'EnterpriseGlobalAccelerationSubscriptionWithPrioritySupport1234567890'],
  ])('为%s套餐标题保留自然换行和两行截断', (_label, name) => {
    const wrapper = mountPlanCard('openai', '', undefined, { name })
    const title = wrapper.get('h3')

    expect(title.text()).toBe(name)
    expect(title.attributes('title')).toBe(name)
    expect(title.classes()).toEqual(expect.arrayContaining([
      'min-w-0',
      'min-h-5',
      'break-words',
      'line-clamp-2',
      '[overflow-wrap:anywhere]',
    ]))
    expect(title.classes()).not.toContain('truncate')
  })

  it('将标题、价格、描述和购买操作保持在独立的稳定区域', () => {
    const wrapper = mountPlanCard('openai', 'USD', undefined, {
      name: 'Enterprise Global Acceleration Subscription with Priority Support',
      price: 123.45,
      description: 'Includes advanced models and priority support.',
    })
    const title = wrapper.get('h3')
    const price = wrapper.findAll('span').find(node => node.text() === '123.45')

    expect(title.element.parentElement?.classList).toContain('min-w-0')
    expect(title.element.parentElement?.classList).toContain('flex-1')
    expect(price?.element.parentElement?.parentElement?.classList).toContain('shrink-0')
    expect(wrapper.get('p').text()).toBe('Includes advanced models and priority support.')
    expect(wrapper.get('button').text()).toBe('payment.subscribeNow')
  })

  it('短标题使用原稿的自然行高，不预留多余的第二行', () => {
    const wrapper = mountPlanCard('openai', '', undefined, { name: 'Pro', description: '' })
    const title = wrapper.get('h3')

    expect(title.text()).toBe('Pro')
    expect(title.attributes('title')).toBe('Pro')
    expect(title.classes()).toEqual(expect.arrayContaining(['text-base', 'font-bold', 'min-h-5', 'leading-tight']))
    expect(title.classes()).not.toContain('h-12')
  })
})
