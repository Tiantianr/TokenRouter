<template>
  <BaseDialog :show="show" :title="t('admin.promptAudit.analysis.title')" width="extra-wide" @close="$emit('close')">
    <div v-if="loading" class="py-12 text-center text-sm text-gray-500" aria-busy="true">
      {{ t('admin.promptAudit.analysis.loading') }}
    </div>
    <div v-else-if="error" role="alert" class="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/30 dark:text-red-300">
      {{ error }}
    </div>
    <div v-else-if="analysis" class="space-y-5">
      <dl class="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
        <div><dt class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.analysis.user') }}</dt><dd class="mt-1 font-medium text-gray-900 dark:text-white">{{ analysis.username || analysis.user_id }}</dd></div>
        <div><dt class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.analysis.session') }}</dt><dd class="mt-1 break-all font-mono text-xs text-gray-800 dark:text-dark-100">{{ shortSessionKey(analysis.session_key) }}</dd></div>
        <div><dt class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.analysis.records') }}</dt><dd class="mt-1 text-gray-900 dark:text-white">{{ analysis.record_count }}</dd></div>
        <div><dt class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.analysis.model') }}</dt><dd class="mt-1 truncate text-gray-900 dark:text-white" :title="analysis.guard_model">{{ analysis.guard_model || analysis.guard_endpoint_name || '—' }}</dd></div>
      </dl>
      <div class="border-t border-gray-200 pt-4 dark:border-dark-700">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.analysis.report') }}</h3>
          <span class="text-xs text-gray-500 dark:text-dark-400">{{ formatDate(analysis.generated_at) }}</span>
        </div>
        <pre class="mt-3 max-h-[min(58vh,38rem)] overflow-auto whitespace-pre-wrap break-words rounded-lg bg-gray-50 p-4 text-sm leading-6 text-gray-700 dark:bg-dark-900 dark:text-dark-200" data-test="user-analysis-report">{{ analysis.report }}</pre>
      </div>
    </div>
  </BaseDialog>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import type { PromptUserAnalysis } from '../types'

defineProps<{ show: boolean; analysis: PromptUserAnalysis | null; loading: boolean; error: string }>()
defineEmits<{ (event: 'close'): void }>()
const { t, locale } = useI18n()

function shortSessionKey(value: string): string {
  if (!value) return '—'
  if (value.length <= 16) return value
  return `${value.slice(0, 8)}...${value.slice(-8)}`
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value))
}
</script>
