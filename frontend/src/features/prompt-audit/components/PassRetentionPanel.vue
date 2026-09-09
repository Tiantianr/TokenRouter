<template>
  <section aria-labelledby="pass-retention-title" class="border-t border-gray-100 py-6 dark:border-dark-800">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="pass-retention-title" class="text-base font-semibold text-gray-950 dark:text-white">
          {{ t('admin.promptAudit.retention.title') }}
        </h2>
        <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">
          {{ t('admin.promptAudit.retention.description') }}
        </p>
      </div>
      <span class="text-xs text-gray-500 dark:text-dark-400">
        {{ t('admin.promptAudit.retention.revision', { revision: config?.revision || 1 }) }}
      </span>
    </div>

    <div v-if="error" role="alert" class="mt-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">
      {{ error }}
    </div>
    <div v-else-if="config?.load_error" role="alert" class="mt-4 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
      {{ t('admin.promptAudit.retention.loadDegraded') }}
    </div>

    <div class="mt-5 max-w-3xl">
      <OpenAIFastPolicyUserSelector :model-value="userIds" @update:model-value="$emit('update:userIds', $event)" />
      <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">
        {{ t('admin.promptAudit.retention.selectedCount', { count: userIds.length }) }}
      </p>
      <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.retention.limitHint') }}</p>
    </div>

    <div class="mt-4 flex flex-wrap items-center gap-3">
      <button type="button" class="btn btn-primary btn-sm" :disabled="!dirty || saving || loading" data-test="save-pass-retention" @click="$emit('save')">
        {{ saving ? t('common.saving') : t('admin.promptAudit.retention.save') }}
      </button>
      <button type="button" class="btn btn-secondary btn-sm" :disabled="!dirty || saving || loading" @click="$emit('reset')">
        {{ t('common.reset') }}
      </button>
      <span v-if="loading" class="text-sm text-gray-500">{{ t('common.loading') }}</span>
      <span v-else class="text-sm" :class="dirty ? 'text-amber-700 dark:text-amber-300' : 'text-gray-500 dark:text-dark-400'">
        {{ dirty ? t('admin.promptAudit.saveBar.dirty') : t('admin.promptAudit.saveBar.synced') }}
      </span>
    </div>
  </section>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import OpenAIFastPolicyUserSelector from '@/views/admin/settings/OpenAIFastPolicyUserSelector.vue'
import type { PromptPassRetentionConfig } from '../types'

defineProps<{
  config: PromptPassRetentionConfig | null
  userIds: number[]
  dirty: boolean
  loading: boolean
  saving: boolean
  error: string
}>()

defineEmits<{
  (event: 'update:userIds', value: number[]): void
  (event: 'save'): void
  (event: 'reset'): void
}>()

const { t } = useI18n()
</script>
