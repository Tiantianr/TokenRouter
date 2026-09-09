<template>
  <section aria-labelledby="prompt-events-title" class="py-6">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="prompt-events-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.events.title') }}</h2>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.events.description') }}</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button type="button" class="btn btn-secondary btn-sm" data-test="cleanup-pass-events" @click="$emit('cleanup-pass')">
          {{ t('admin.promptAudit.cleanup.action') }}
        </button>
        <button type="button" class="btn btn-secondary btn-sm" :disabled="selectedIds.length === 0" @click="$emit('batch-delete')">
          {{ t('admin.promptAudit.events.deleteSelected', { count: selectedIds.length }) }}
        </button>
        <button type="button" class="btn btn-danger btn-sm" data-test="filter-delete" @click="$emit('preview-delete')">
          {{ t('admin.promptAudit.events.deleteByFilter') }}
        </button>
      </div>
    </div>

    <form class="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5" @submit.prevent="applyFilters">
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.decision') }}</span>
        <Select v-model="localFilters.decision" class="mt-1 w-full" :aria-label="t('admin.promptAudit.events.decision')" @change="filtersChanged" :options="[{ value: '', label: t('common.all') }, { value: 'pass', label: t('admin.promptAudit.decisions.pass') }, { value: 'flag', label: t('admin.promptAudit.decisions.flag') }, { value: 'critical', label: t('admin.promptAudit.decisions.critical') }, { value: 'failed', label: t('admin.promptAudit.decisions.failed') }]" />
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.risk') }}</span>
        <Select v-model="localFilters.risk_level" class="mt-1 w-full" :aria-label="t('admin.promptAudit.events.risk')" @change="filtersChanged" :options="[{ value: '', label: t('common.all') }, { value: 'low', label: t('admin.promptAudit.riskLevels.low') }, { value: 'medium', label: t('admin.promptAudit.riskLevels.medium') }, { value: 'high', label: t('admin.promptAudit.riskLevels.high') }, { value: 'critical', label: t('admin.promptAudit.riskLevels.critical') }, { value: 'unknown', label: t('admin.promptAudit.riskLevels.unknown') }]" />
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.executionMode') }}</span>
        <Select v-model="localFilters.execution_mode" class="mt-1 w-full" :aria-label="t('admin.promptAudit.events.executionMode')" @change="filtersChanged" :options="[{ value: '', label: t('common.all') }, { value: 'blocking', label: t('admin.promptAudit.mode.blocking') }, { value: 'async_audit', label: t('admin.promptAudit.mode.async_audit') }, { value: 'async_deep', label: t('admin.promptAudit.mode.async_deep') }]" />
      </label>
      <FilterInput v-model="localFilters.endpoint" :label="t('admin.promptAudit.events.endpoint')" @change="filtersChanged" />
      <FilterInput v-model="localFilters.client_ip" :label="t('admin.promptAudit.events.clientIp')" @change="filtersChanged" />
      <FilterInput v-model="localFilters.group_id" :label="t('admin.promptAudit.events.groupId')" type="number" @change="filtersChanged" />
      <FilterInput v-model="localFilters.user_id" :label="t('admin.promptAudit.events.userId')" type="number" @change="filtersChanged" />
      <FilterInput :model-value="localFilters.session_id || ''" :label="t('admin.promptAudit.sessions.sessionId')" type="number" @update:model-value="localFilters.session_id = $event" @change="filtersChanged" />
      <FilterInput v-model="localFilters.api_key_id" :label="t('admin.promptAudit.events.apiKeyId')" type="number" @change="filtersChanged" />
      <FilterInput v-model="localFilters.request_id" :label="t('admin.promptAudit.events.requestId')" @change="filtersChanged" />
      <FilterInput v-model="localFilters.prompt_hash" :label="t('admin.promptAudit.events.promptHash')" @change="filtersChanged" />
      <FilterInput v-model="localFilters.keyword" :label="t('admin.promptAudit.events.keyword')" @change="filtersChanged" />
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.startAt') }}</span>
        <input v-model="localFilters.start_at" type="datetime-local" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.startAt')" @change="filtersChanged" />
      </label>
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.events.endAt') }}</span>
        <input v-model="localFilters.end_at" type="datetime-local" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.endAt')" @change="filtersChanged" />
      </label>
      <div class="flex items-end gap-2 sm:col-span-2">
        <button type="submit" class="btn btn-primary btn-sm">{{ t('common.search') }}</button>
        <button type="button" class="btn btn-ghost btn-sm" @click="resetFilters">{{ t('common.reset') }}</button>
      </div>
    </form>
    <div v-if="error" role="alert" class="mt-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">{{ error }}</div>
    <div class="mt-5 overflow-x-auto rounded-xl border border-gray-200 dark:border-dark-700/60">
      <table class="min-w-[1580px] w-full text-left text-sm">
        <thead class="bg-gray-50 text-xs uppercase tracking-wide text-gray-500 dark:bg-dark-900/70 dark:text-dark-400">
          <tr>
            <th class="w-10 px-3 py-3"><input type="checkbox" :checked="allSelected" :aria-label="t('admin.promptAudit.events.selectAll')" @change="toggleAll" /></th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.time') }}</th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.clientIp') }}</th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.identity') }}</th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.group') }}</th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.route') }}</th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.auditNode') }}</th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.result') }}</th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.durations') }}</th>
            <th class="px-3 py-3 font-medium">{{ t('admin.promptAudit.events.preview') }}</th>
            <th class="px-3 py-3 text-right font-medium">{{ t('admin.promptAudit.common.actions') }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 bg-white dark:divide-dark-700 dark:bg-transparent">
          <tr v-if="loading"><td colspan="11" class="px-4 py-12 text-center text-gray-500" aria-busy="true">{{ t('common.loading') }}</td></tr>
          <tr v-else-if="events.length === 0"><td colspan="11" class="px-4 py-12 text-center text-gray-500">{{ t('admin.promptAudit.events.empty') }}</td></tr>
          <tr v-for="event in events" v-else :key="event.id" :data-test="`event-${event.id}`" class="align-top hover:bg-gray-50/70 dark:hover:bg-dark-800/70" :class="isFailed(event) ? 'bg-red-50/40 dark:bg-red-950/10' : ''">
            <td class="px-3 py-3"><input type="checkbox" :checked="selectedIds.includes(event.id)" :aria-label="t('admin.promptAudit.events.selectEvent', { id: event.id })" @change="toggleOne(event.id)" /></td>
            <td class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300">{{ formatDate(event.created_at) }}</td>
            <td class="px-3 py-3">
              <button
                v-if="event.snapshot.client_ip"
                type="button"
                class="font-mono text-xs text-primary-600 hover:underline dark:text-primary-300"
                :title="t('admin.promptAudit.events.filterByIp', { ip: event.snapshot.client_ip })"
                :aria-label="t('admin.promptAudit.events.filterByIp', { ip: event.snapshot.client_ip })"
                @click="filterByIP(event.snapshot.client_ip)"
              >
                {{ event.snapshot.client_ip }}
              </button>
              <span v-else>—</span>
            </td>
            <td class="px-3 py-3">
              <div class="flex max-w-56 items-center gap-1 text-xs">
                <span class="w-16 flex-none text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.events.userId') }}</span>
                <button
                  v-if="event.snapshot.user_id > 0"
                  type="button"
                  class="min-w-0 flex-1 truncate text-left font-mono text-primary-600 hover:underline dark:text-primary-300"
                  :title="t('admin.promptAudit.events.filterByUserId', { id: event.snapshot.user_id })"
                  :aria-label="t('admin.promptAudit.events.filterByUserId', { id: event.snapshot.user_id })"
                  @click="filterByUserID(event.snapshot.user_id)"
                >
                  {{ event.snapshot.user_id }}
                </button>
                <span v-else>—</span>
              </div>
              <CopyLine :label="t('admin.promptAudit.events.user')" :value="event.snapshot.username" />
              <CopyLine :label="t('admin.promptAudit.events.email')" :value="event.snapshot.user_email" />
              <CopyLine :label="t('admin.promptAudit.events.apiKey')" :value="event.snapshot.api_key_name" />
            </td>
            <td class="px-3 py-3 text-gray-700 dark:text-dark-200">{{ event.snapshot.group_name || '—' }}</td>
            <td class="px-3 py-3">
              <p class="font-medium text-gray-900 dark:text-white">{{ event.snapshot.endpoint }}</p>
              <p class="mt-1 text-xs text-gray-500">{{ event.snapshot.model }} · {{ event.snapshot.protocol }} · {{ event.snapshot.stage || 'http' }}</p>
            </td>
            <td class="max-w-52 px-3 py-3" data-test="audit-node">
              <p class="truncate font-medium text-gray-900 dark:text-white" :title="event.guard_endpoint_name || event.guard_endpoint_id">{{ event.guard_endpoint_name || event.guard_endpoint_id || '—' }}</p>
              <p class="mt-1 truncate text-xs text-gray-500" :title="event.guard_model || event.scanner_version">{{ event.guard_model || event.scanner_version || '—' }}</p>
              <p v-if="event.guard_endpoint_name && event.guard_endpoint_id" class="mt-1 truncate font-mono text-xs text-gray-400" :title="event.guard_endpoint_id">{{ event.guard_endpoint_id }}</p>
            </td>
            <td class="px-3 py-3">
              <template v-if="isFailed(event)">
                <span class="rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-700 dark:bg-red-950/50 dark:text-red-300">{{ translateDecision(event.decision) }}</span>
                <p class="mt-2 max-w-52 text-xs font-medium text-red-700 dark:text-red-300">{{ failureReason(event) }}</p>
                <p v-if="event.error_code" class="mt-1 max-w-52 truncate font-mono text-xs text-gray-600 dark:text-dark-300" :title="event.error_code">{{ event.error_code }}</p>
              </template>
              <template v-else>
                <span class="rounded-full px-2 py-0.5 text-xs font-medium" :class="decisionClass(event.decision)">{{ formatDecisionRisk(event.decision, event.risk_level) }}</span>
                <p class="mt-2 max-w-48 truncate text-xs text-gray-500" :title="formatCategories(event.matched_scanners)">{{ formatCategories(event.matched_scanners) }}</p>
              </template>
            </td>
            <td class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300">
              <p>{{ t('admin.promptAudit.events.queueDelay') }} · {{ formatDuration(event.queue_delay_ms) }}</p>
              <p class="mt-1">{{ t('admin.promptAudit.events.auditLatency') }} · {{ formatDuration(event.latency_ms) }}</p>
              <p class="mt-1 text-gray-400 dark:text-dark-500">{{ formatMode(event.execution_mode) }}</p>
              <span
                v-if="event.snapshot.blocking_exempt_at_request"
                class="mt-1 inline-flex rounded-full bg-cyan-100 px-2 py-0.5 text-xs font-medium text-cyan-800 dark:bg-cyan-950/50 dark:text-cyan-200"
                data-test="blocking-exempt-at-request"
                :title="t('admin.promptAudit.events.blockingExemptAtRequestHint')"
              >
                {{ t('admin.promptAudit.events.blockingExemptAtRequest') }}
              </span>
            </td>
            <td class="whitespace-nowrap px-3 py-3 text-xs text-gray-600 dark:text-dark-300">
              <p>{{ t('admin.promptAudit.events.queueDelay') }} · {{ formatDuration(event.queue_delay_ms) }}</p>
              <p class="mt-1">{{ t('admin.promptAudit.events.auditLatency') }} · {{ formatDuration(event.latency_ms) }}</p>
              <p class="mt-1 text-gray-400 dark:text-dark-500">{{ formatMode(event.execution_mode) }}</p>
            </td>
            <td class="max-w-xs px-3 py-3"><p class="line-clamp-2 break-words text-gray-600 dark:text-dark-300">{{ event.snapshot.redacted_preview || '—' }}</p></td>
            <td class="whitespace-nowrap px-3 py-3 text-right">
              <button type="button" class="btn btn-ghost btn-sm" @click="$emit('view', event.id)">{{ t('common.view') }}</button>
              <button
                type="button"
                class="btn btn-ghost btn-sm"
                :disabled="event.snapshot.user_id <= 0"
                :title="t('admin.promptAudit.analysis.action')"
                :aria-label="t('admin.promptAudit.analysis.action')"
                data-test="analyze-user"
                @click="$emit('analyze', event.id)"
              >
                <Icon name="brain" size="sm" class="mr-1" />
                {{ t('admin.promptAudit.analysis.action') }}
              </button>
              <button type="button" class="btn btn-ghost btn-sm text-red-600" @click="$emit('delete', event.id)">{{ t('common.delete') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
      <Pagination :total="total" :page="page" :page-size="pageSize" @update:page="$emit('page', $event)" @update:page-size="$emit('page-size', $event)" />
    </div>
  </section>
</template>

<script setup lang="ts">
import Select from '@/components/common/Select.vue'
import { computed, defineComponent, h, reactive, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Pagination from '@/components/common/Pagination.vue'
import Icon from '@/components/icons/Icon.vue'
import type { PromptAuditEvent, PromptEventFilters } from '../types'
import { cloneData, emptyEventFilters, SCANNER_CATALOG } from '../viewModel'

const props = defineProps<{
  events: PromptAuditEvent[]; total: number; page: number; pageSize: number
  filters: PromptEventFilters; selectedIds: number[]; loading: boolean; error: string
}>()
const emit = defineEmits<{
  (event: 'filters-change', value: PromptEventFilters): void
  (event: 'search', value: PromptEventFilters): void
  (event: 'selection', value: number[]): void
  (event: 'page', value: number): void
  (event: 'page-size', value: number): void
  (event: 'view', id: number): void
  (event: 'analyze', id: number): void
  (event: 'delete', id: number): void
  (event: 'batch-delete'): void
  (event: 'preview-delete'): void
  (event: 'cleanup-pass'): void
}>()
const { t, locale } = useI18n()
const localFilters = reactive<PromptEventFilters>(cloneData(props.filters))
watch(() => props.filters, (value) => Object.assign(localFilters, cloneData(value)), { deep: true })
const allSelected = computed(() => props.events.length > 0 && props.events.every((event) => props.selectedIds.includes(event.id)))

const FilterInput = defineComponent({
  props: { modelValue: { type: String, required: true }, label: { type: String, required: true }, type: { type: String, default: 'text' } },
  emits: ['update:modelValue', 'change'],
  setup(componentProps, { emit: componentEmit }) {
    return () => h('label', { class: 'text-xs text-gray-600 dark:text-dark-200' }, [
      h('span', componentProps.label),
      h('input', {
        value: componentProps.modelValue, type: componentProps.type, class: 'input mt-1 w-full', 'aria-label': componentProps.label,
        onInput: (event: Event) => componentEmit('update:modelValue', (event.target as HTMLInputElement).value),
        onChange: () => componentEmit('change'),
      }),
    ])
  },
})

const CopyLine = defineComponent({
  props: { label: { type: String, required: true }, value: { type: String, default: '' } },
  setup(componentProps) {
    return () => h('div', { class: 'flex max-w-56 items-center gap-1 text-xs' }, [
      h('span', { class: 'w-16 flex-none text-gray-500 dark:text-dark-400' }, componentProps.label),
      h('span', { class: 'min-w-0 flex-1 truncate text-gray-800 dark:text-dark-100' }, componentProps.value || '—'),
      componentProps.value ? h('button', {
        type: 'button', class: 'text-primary-600 hover:underline', 'aria-label': `${t('common.copy')} ${componentProps.label}`,
        onClick: () => navigator.clipboard?.writeText(componentProps.value),
      }, t('common.copy')) : null,
    ])
  },
})

function filtersChanged() {
  emit('filters-change', cloneData(localFilters))
}
function applyFilters() {
  const value = cloneData(localFilters)
  emit('filters-change', value)
  emit('search', value)
}
function resetFilters() {
  Object.assign(localFilters, emptyEventFilters())
  applyFilters()
}
function filterByIP(value: string) {
  localFilters.client_ip = value
  applyFilters()
}
function filterByUserID(value: number) {
  localFilters.user_id = String(value)
  applyFilters()
}
function toggleOne(id: number) {
  const selected = new Set(props.selectedIds)
  if (selected.has(id)) selected.delete(id)
  else selected.add(id)
  emit('selection', [...selected])
}
function toggleAll() {
  emit('selection', allSelected.value ? [] : props.events.map((event) => event.id))
}
function formatDate(value: string): string {
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value))
}
function formatDuration(value?: number | null): string {
  if (value == null) return '—'
  if (value < 1000) return `${value} ms`
  return `${(value / 1000).toFixed(value < 10000 ? 2 : 1)} s`
}
function formatMode(mode?: string): string {
  if (!mode) return '—'
  const key = `admin.promptAudit.mode.${mode}`
  const label = t(key)
  return label === key ? mode : label
}
function decisionClass(decision: string): string {
  if (decision === 'failed' || decision === 'critical') return 'bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300'
  if (decision === 'flag') return 'bg-amber-100 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300'
  return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300'
}
const DECISIONS = new Set(['pass', 'flag', 'critical', 'failed'])
const RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical', 'unknown'])

function translateDecision(decision: string): string {
  return DECISIONS.has(decision) ? t(`admin.promptAudit.decisions.${decision}`) : decision
}
function translateRiskLevel(riskLevel: string): string {
  return RISK_LEVELS.has(riskLevel) ? t(`admin.promptAudit.riskLevels.${riskLevel}`) : riskLevel
}
function translateCategory(category: string): string {
  return SCANNER_CATALOG.some((scanner) => scanner.id === category)
    ? t(`admin.promptAudit.scanners.${category}`)
    : category
}
function isFailed(event: PromptAuditEvent): boolean {
  return event.decision === 'failed'
}
function failureReason(event: PromptAuditEvent): string {
  const code = event.error_code
  if (code) {
    const key = `admin.promptAudit.events.failureReasons.${code}`
    const label = t(key)
    if (label !== key) return label
  }
  return event.error_message || code || t('admin.promptAudit.events.failureReasonFallback')
}
function formatDecisionRisk(decision: string, riskLevel: string): string {
  return `${translateDecision(decision)} · ${translateRiskLevel(riskLevel)}`
}
function formatCategories(categories: string[]): string {
  if (!categories.length) return '—'
  return categories.map(translateCategory).join(', ')
}
</script>
