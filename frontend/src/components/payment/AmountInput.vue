<template>
  <div class="space-y-4">
    <!-- 币种和倍率由购买页传入，避免切换支付方式后仍显示美元。 -->
    <div>
      <div class="mb-4 flex flex-wrap items-center gap-2">
        <span class="text-base font-bold text-accent-800 dark:text-white">{{ t('payment.quickAmounts') }}</span>
        <span v-if="rateHint" class="max-w-full break-words rounded bg-accent-100 px-2 py-0.5 text-xs text-accent-500 dark:bg-dark-700 dark:text-gray-400">{{ rateHint }}</span>
      </div>
      <div class="grid grid-cols-3 gap-2">
        <button
          v-for="amt in filteredAmounts"
          :key="amt"
          type="button"
          :aria-pressed="modelValue === amt && !isCustomActive"
          :class="[
            'min-h-11 min-w-0 break-words rounded-[12px] border-2 px-2 py-2 text-center text-base font-medium transition-colors',
            modelValue === amt && !isCustomActive
              ? 'border-blue-600 bg-blue-50 text-blue-700 dark:border-blue-500 dark:bg-blue-950/40 dark:text-blue-300'
              : 'border-accent-100 bg-white text-accent-700 hover:border-blue-200 hover:bg-blue-50/50 dark:border-dark-700 dark:bg-dark-800 dark:text-gray-200 dark:hover:border-dark-500',
          ]"
          @click="selectAmount(amt)"
        >
          {{ currencySymbol }} {{ amt }}
        </button>
      </div>
    </div>

    <label class="block">
      <span class="mb-3 block text-sm font-bold text-accent-800 dark:text-white">{{ t('payment.customAmount') }}</span>
      <span :class="['flex min-h-11 min-w-0 items-center gap-2 rounded-[12px] border-2 px-4 transition-colors focus-within:border-blue-600', isCustomActive ? 'border-blue-600 bg-white shadow-[0_1px_2px_0_rgb(0_0_0/0.05)] focus-within:ring-4 focus-within:ring-blue-600/10 dark:border-blue-500' : 'border-accent-200 bg-accent-50 dark:border-dark-600', 'dark:bg-dark-800']">
        <span class="shrink-0 font-medium text-gray-400">{{ currencySymbol }}</span>
        <input
          type="text"
          inputmode="decimal"
          :value="customText"
          :placeholder="placeholderText"
          class="min-w-0 flex-1 border-0 bg-transparent py-2 text-base font-medium text-accent-800 outline-none focus:ring-0 dark:text-white"
          @input="handleInput"
        />
      </span>
    </label>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const props = withDefaults(defineProps<{
  amounts?: number[]
  modelValue: number | null
  min?: number
  max?: number
  currencySymbol?: string
  currency?: string
  rateHint?: string
}>(), {
  amounts: () => [10, 20, 50, 100, 200, 500, 1000, 2000, 5000],
  min: 0,
  max: 0,
  currencySymbol: '$',
  currency: '',
  rateHint: '',
})

const emit = defineEmits<{
  'update:modelValue': [value: number | null]
}>()

const { t } = useI18n()

const customText = ref('')
const isCustomActive = computed(() => customText.value !== '')

// 零表示不限额，快捷金额仍须经过支付方式限额过滤。
const filteredAmounts = computed(() =>
  props.amounts.filter((a) => (props.min <= 0 || a >= props.min) && (props.max <= 0 || a <= props.max))
)

const placeholderText = computed(() => {
  if (props.min > 0 && props.max > 0) return `${props.min} - ${props.max}`
  if (props.min > 0) return props.currency ? t('payment.enterAmountWithMinimum', { min: props.min, currency: props.currency }) : `≥ ${props.min}`
  if (props.max > 0) return `≤ ${props.max}`
  return t('payment.enterAmount')
})

const AMOUNT_PATTERN = /^\d*(\.\d{0,2})?$/

function selectAmount(amt: number) {
  // 快捷金额与自定义输入是两种选择，点快捷金额后保留输入框占位提示。
  customText.value = ''
  emit('update:modelValue', amt)
}

function handleInput(e: Event) {
  const val = (e.target as HTMLInputElement).value
  if (!AMOUNT_PATTERN.test(val)) {
    // 非法输入不更新金额，并恢复可见文本，避免展示值与实际下单值不一致。
    (e.target as HTMLInputElement).value = customText.value
    return
  }
  customText.value = val
  if (val === '') {
    emit('update:modelValue', null)
    return
  }
  const num = parseFloat(val)
  if (!isNaN(num) && num > 0) {
    emit('update:modelValue', num)
  } else {
    emit('update:modelValue', null)
  }
}

watch(() => props.modelValue, (v) => {
  if (v === null) {
    customText.value = ''
  } else if (Number(customText.value) !== v) {
    customText.value = filteredAmounts.value.includes(v) ? '' : String(v)
  }
}, { immediate: true })
</script>
