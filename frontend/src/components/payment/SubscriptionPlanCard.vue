<template>
  <div
    :class="[
      'group relative flex min-w-0 cursor-pointer flex-col rounded-[16px] border-2 bg-white p-5 transition-all duration-300 motion-reduce:transition-none dark:bg-dark-800',
      selected ? 'border-blue-600 shadow-xl shadow-blue-900/5 dark:border-blue-500 lg:-translate-y-2 motion-reduce:transform-none' : 'border-transparent shadow-[0_1px_2px_0_rgb(0_0_0/0.05)] hover:border-blue-200 hover:shadow-md dark:border-dark-700 dark:hover:border-dark-500',
    ]"
    @click="emit('select', plan)"
  >
    <!-- 原稿的推荐标记依赖演示数据，真实页面只突出用户已选择的套餐。 -->
    <div v-if="selected" data-testid="plan-selected-badge" class="absolute -top-4 left-1/2 flex min-h-6 max-w-[calc(100%-24px)] -translate-x-1/2 items-center justify-center gap-1 whitespace-nowrap rounded-full bg-blue-600 px-4 py-1 text-xs font-bold text-white shadow-md">
      <Icon name="check" size="xs" />
      {{ t('payment.selectedPlan') }}
    </div>
    <div class="flex min-w-0 flex-1 flex-col">
      <!-- 标题与价格分行，保证长套餐名不会挤压金额。 -->
      <div class="mb-3 space-y-4">
        <div class="min-w-0 flex-1">
          <h3
            :title="plan.name"
            class="min-h-5 min-w-0 break-words [overflow-wrap:anywhere] pr-2 text-base font-bold leading-tight text-accent-900 dark:text-white line-clamp-2"
          >
            {{ plan.name }}
          </h3>
          <div class="mt-1.5 flex flex-wrap items-center gap-2">
            <span v-if="platform" class="rounded bg-blue-50 px-2 py-0.5 text-xs font-medium text-blue-600 dark:bg-blue-950/40 dark:text-blue-400">{{ platformLabel(platform) }}</span>
            <span class="text-xs text-accent-500 dark:text-gray-400">/ {{ validitySuffix }}</span>
          </div>
        </div>
        <div class="min-w-0 shrink-0">
          <div class="mb-1 flex flex-wrap items-baseline gap-1">
            <span class="text-xl font-semibold text-accent-700 dark:text-gray-300">{{ planCurrencySymbol }}</span>
            <span class="max-w-full break-words text-3xl font-black text-accent-900 [overflow-wrap:anywhere] dark:text-white">{{ plan.price }}</span>
            <span v-if="plan.currency" class="ml-1 text-sm font-medium text-accent-500 dark:text-gray-400">{{ plan.currency }}</span>
          </div>
          <div v-if="plan.original_price" class="flex flex-wrap items-center gap-2">
            <span class="text-xs text-accent-400 line-through dark:text-gray-500">{{ planCurrencySymbol }}{{ plan.original_price }}<template v-if="plan.currency"> {{ plan.currency }}</template></span>
            <span v-if="discountText" class="rounded bg-red-50 px-1.5 py-0.5 text-xs font-bold text-red-600 dark:bg-red-950/40 dark:text-red-400">{{ discountText }}</span>
          </div>
        </div>
      </div>
      <p class="h-9 break-words text-xs leading-relaxed text-accent-500 line-clamp-2 dark:text-gray-400" :title="plan.description">{{ plan.description }}</p>

      <!-- 指标沿用参考版的浅色底与竖分隔线，同时保留所有已配置的额度。 -->
      <div data-testid="plan-metrics" :class="['mt-4 grid rounded-[12px] bg-accent-50 p-3 dark:bg-dark-700/50', metrics.length === 3 ? 'grid-cols-3' : 'grid-cols-2']">
        <div v-for="(metric, index) in metrics" :key="metric.label"
          :class="['min-w-0 px-2 text-center', index % (metrics.length === 3 ? 3 : 2) !== 0 ? 'border-l border-accent-200 dark:border-dark-600' : '', metrics.length === 4 && index >= 2 ? 'mt-3' : '']">
          <div class="mb-1 text-xs text-accent-500 dark:text-gray-400">{{ metric.label }}</div>
          <div class="break-words text-sm font-bold text-accent-800 [overflow-wrap:anywhere] dark:text-white">{{ metric.value }}</div>
        </div>
      </div>
      <div v-if="modelScopeLabels.length > 0" class="mt-2.5 flex flex-wrap justify-center gap-1">
        <span v-for="scope in modelScopeLabels" :key="scope" class="rounded bg-accent-200/80 px-1.5 py-0.5 text-[10px] font-medium text-accent-600 dark:bg-dark-600 dark:text-gray-300">{{ scope }}</span>
      </div>

      <!-- 功能列表保留完整文案，随内容自然增高，不截断权益说明。 -->
      <div v-if="plan.features.length > 0" class="mt-4 space-y-2">
        <div v-for="feature in plan.features" :key="feature" class="flex items-start gap-2">
          <span class="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-950/80"><Icon name="check" size="xs" :stroke-width="3" class="text-blue-600 dark:text-blue-400" /></span>
          <span class="min-w-0 break-words text-xs leading-tight text-accent-600 [overflow-wrap:anywhere] dark:text-gray-300">{{ feature }}</span>
        </div>
      </div>

      <div class="flex-1" />

      <!-- 使用原生按钮承载选择操作，键盘与鼠标共用同一事件。 -->
      <button
        type="button"
        :aria-pressed="selected"
        :class="['mt-5 min-h-10 w-full rounded-[12px] px-3 py-2.5 text-sm font-bold transition-colors', selected ? 'bg-blue-600 text-white shadow-md shadow-blue-600/20 hover:bg-blue-700' : 'bg-accent-100 text-accent-700 hover:bg-accent-200 dark:bg-dark-700 dark:text-gray-200 dark:hover:bg-dark-600']"
        @click.stop="emit('select', plan)"
      >
        {{ isRenewal ? t('payment.renewNow') : t('payment.subscribeNow') }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SubscriptionPlan } from '@/types/payment'
import type { UserSubscription } from '@/types'
import Icon from '@/components/icons/Icon.vue'
import { platformLabel } from '@/utils/platformColors'
import { useBalanceDisplay } from '@/composables/useBalanceDisplay'
import { currencySymbol } from '@/components/payment/currency'
import { planValiditySuffix } from './validity'

const props = withDefaults(defineProps<{ plan: SubscriptionPlan; activeSubscriptions?: UserSubscription[]; selected?: boolean }>(), { selected: false })
const emit = defineEmits<{ select: [plan: SubscriptionPlan] }>()
const { t } = useI18n()
const { formatBalanceAmount } = useBalanceDisplay()
const planCurrencySymbol = computed(() => currencySymbol(props.plan.currency || 'USD'))

const platform = computed(() => props.plan.group_platform || '')
const isRenewal = computed(() =>
  props.activeSubscriptions?.some(s => s.plan_id === props.plan.id && s.status === 'active') ?? false
)

const discountText = computed(() => {
  if (!props.plan.original_price || props.plan.original_price <= 0) return ''
  const pct = Math.round((1 - props.plan.price / props.plan.original_price) * 100)
  return pct > 0 ? `-${pct}%` : ''
})

function formatPlanQuota(value: number | null | undefined): string {
  const amount = Number(value)
  return formatBalanceAmount(value, { fractionDigits: Number.isInteger(amount) ? 0 : 2 })
}

function hasPlanQuota(value: number | null | undefined): boolean {
  return value != null && value > 0
}

const rateDisplay = computed(() => {
  // 只有接口完整给出适用分组的倍率时才展示数值，缺失项仍由分组默认倍率决定。
  const groupIds = props.plan.group_ids ?? (props.plan.group_id ? [props.plan.group_id] : [])
  const groupRates = props.plan.group_rate_multipliers as Record<number, number> | undefined
  const rates = groupIds.map(id => groupRates?.[id])
  if (rates.length > 0 && rates.every((rate): rate is number => typeof rate === 'number' && Number.isFinite(rate) && rate >= 0)) {
    const min = Math.min(...rates)
    const max = Math.max(...rates)
    return min === max ? `x${min}` : `x${min} ~ x${max}`
  }
  if (props.plan.rate_multiplier != null && Number.isFinite(props.plan.rate_multiplier) && props.plan.rate_multiplier >= 0) {
    return `x${props.plan.rate_multiplier}`
  }
  return t('payment.planCard.rateByGroup')
})

const metrics = computed(() => {
  const values = [{ label: t('payment.planCard.rate'), value: rateDisplay.value }]
  for (const [key, value] of [
    ['dailyLimit', props.plan.daily_limit_usd],
    ['weeklyLimit', props.plan.weekly_limit_usd],
    ['monthlyLimit', props.plan.monthly_limit_usd],
  ] as const) {
    if (hasPlanQuota(value)) values.push({ label: t(`payment.planCard.${key}`), value: formatPlanQuota(value) })
  }
  if (values.length === 1) values.push({ label: t('payment.planCard.quota'), value: t('payment.planCard.unlimited') })
  return values
})

const MODEL_SCOPE_LABELS: Record<string, string> = {
  claude: 'Claude',
  gemini_text: 'Gemini',
  gemini_image: 'Imagen',
}

const modelScopeLabels = computed(() => {
  // 模型系列只对 Antigravity 套餐有含义，其他平台不展示历史残留字段。
  if (platform.value !== 'antigravity') return []
  const scopes = props.plan.supported_model_scopes
  if (!scopes || scopes.length === 0) return []
  return scopes.map(s => MODEL_SCOPE_LABELS[s] || s)
})

const validitySuffix = computed(() => {
  return planValiditySuffix(props.plan, t)
})
</script>
