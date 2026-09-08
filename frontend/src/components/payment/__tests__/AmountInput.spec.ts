import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import AmountInput from '../AmountInput.vue'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

// 使用父组件回写模拟 v-model，覆盖展示文本和实际金额的一致性。
function mountAmountInput() {
  const wrapper = mount(AmountInput, {
    props: {
      modelValue: null,
      amounts: [10, 20, 50, 100, 200, 500],
      currencySymbol: 'NZ$',
      rateHint: '1 NZD = 0.60 USD',
      min: 20,
      max: 200,
      'onUpdate:modelValue': (value: number | null) => { void wrapper.setProps({ modelValue: value }) },
    },
  })
  return wrapper
}

describe('AmountInput', () => {
  it('按限额筛选快捷金额，并使用当前币种与倍率', async () => {
    const wrapper = mountAmountInput()
    expect(wrapper.findAll('button').map(button => button.text())).toEqual(['NZ$ 20', 'NZ$ 50', 'NZ$ 100', 'NZ$ 200'])
    expect(wrapper.text()).toContain('1 NZD = 0.60 USD')
    await wrapper.get('button').trigger('click')
    expect(wrapper.props('modelValue')).toBe(20)
    expect(wrapper.get('input').element.value).toBe('')
    expect(wrapper.get('button').attributes('aria-pressed')).toBe('true')
  })

  it('自定义金额可切回快捷金额，并响应父级清空', async () => {
    const wrapper = mountAmountInput()
    await wrapper.get('input').setValue('88.50')
    expect(wrapper.props('modelValue')).toBe(88.5)
    expect(wrapper.findAll('button').every(button => button.attributes('aria-pressed') === 'false')).toBe(true)
    await wrapper.get('button').trigger('click')
    expect(wrapper.get('input').element.value).toBe('')
    await wrapper.setProps({ modelValue: null })
    expect(wrapper.get('input').element.value).toBe('')
    expect(wrapper.get('button').attributes('aria-pressed')).toBe('false')
  })

  it('拒绝非法文本时保持可见金额与下单金额一致', async () => {
    const wrapper = mountAmountInput()
    await wrapper.get('input').setValue('20')
    await wrapper.get('input').setValue('20abc')
    expect(wrapper.props('modelValue')).toBe(20)
    expect(wrapper.get('input').element.value).toBe('20')
    await wrapper.get('input').setValue('')
    expect(wrapper.props('modelValue')).toBeNull()
  })

  it('手动输入快捷金额时仍突出自定义输入，点击快捷按钮后恢复占位提示', async () => {
    const wrapper = mountAmountInput()
    await wrapper.get('input').setValue('20')
    expect(wrapper.get('button').attributes('aria-pressed')).toBe('false')
    await wrapper.get('button').trigger('click')
    expect(wrapper.get('button').attributes('aria-pressed')).toBe('true')
    expect(wrapper.get('input').element.value).toBe('')
    expect(wrapper.props('modelValue')).toBe(20)
  })
})
