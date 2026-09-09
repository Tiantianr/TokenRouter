<template>
  <BaseDialog :show="show" :title="t('admin.promptAudit.cleanup.title')" width="wide" @close="$emit('close')">
    <div class="space-y-5 text-sm">
      <p class="text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.cleanup.description') }}</p>

      <fieldset>
        <legend class="text-xs font-medium text-gray-600 dark:text-dark-200">{{ t('admin.promptAudit.cleanup.userScope') }}</legend>
        <div class="mt-2 flex gap-5 text-sm text-gray-700 dark:text-dark-200">
          <label class="flex items-center gap-2">
            <input v-model="allUsers" type="radio" :value="true" name="pass-cleanup-user-scope" @change="criteriaChanged" />
            {{ t('admin.promptAudit.cleanup.allUsers') }}
          </label>
          <label class="flex items-center gap-2">
            <input v-model="allUsers" type="radio" :value="false" name="pass-cleanup-user-scope" @change="criteriaChanged" />
            {{ t('admin.promptAudit.cleanup.selectedUser') }}
          </label>
        </div>
        <div v-if="!allUsers" class="mt-3">
          <OpenAIFastPolicyUserSelector :model-value="selectedUserIDs" @update:model-value="selectOneUser" />
          <p v-if="selectedUserIDs.length === 0" class="mt-2 text-xs text-red-600 dark:text-red-400">{{ t('admin.promptAudit.cleanup.userRequired') }}</p>
        </div>
      </fieldset>

      <fieldset>
        <legend class="text-xs font-medium text-gray-600 dark:text-dark-200">{{ t('admin.promptAudit.events.filterTimeRange') }}</legend>
        <div class="mt-2 flex flex-wrap gap-2" role="radiogroup" :aria-label="t('admin.promptAudit.events.filterTimeRange')">
          <label v-for="option in DELETE_RANGE_PRESETS" :key="option.id" class="cursor-pointer">
            <input v-model="preset" type="radio" name="pass-cleanup-range" :value="option.id" class="peer sr-only" :data-test="`pass-cleanup-range-${option.id}`" @change="criteriaChanged" />
            <span class="inline-flex items-center rounded-full border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors peer-checked:border-red-500 peer-checked:bg-red-50 peer-checked:text-red-700 dark:border-dark-600 dark:text-dark-300 dark:peer-checked:border-red-500 dark:peer-checked:bg-red-950/40 dark:peer-checked:text-red-300">
              {{ t(`admin.promptAudit.events.timePresets.${option.id}`) }}
            </span>
          </label>
        </div>
        <div v-if="preset === 'custom'" class="mt-3 grid gap-3 sm:grid-cols-2">
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.events.startAt') }}</span>
            <input v-model="customStart" type="datetime-local" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.startAt')" @change="criteriaChanged" />
          </label>
          <label class="text-xs text-gray-600 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.events.endAt') }}</span>
            <input v-model="customEnd" type="datetime-local" class="input mt-1 w-full" :aria-label="t('admin.promptAudit.events.endAt')" @change="criteriaChanged" />
          </label>
        </div>
      </fieldset>

      <div v-if="preview" class="rounded-lg border border-red-200 bg-red-50/60 px-4 py-3 dark:border-red-900/60 dark:bg-red-950/20" data-test="pass-cleanup-preview">
        <p class="font-semibold text-red-700 dark:text-red-300">{{ t('admin.promptAudit.cleanup.matched', { count: preview.matched_count }) }}</p>
        <dl class="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs text-gray-600 dark:text-dark-300">
          <dt>{{ t('admin.promptAudit.cleanup.contexts') }}</dt><dd>{{ preview.matched_context_count }}</dd>
          <dt>{{ t('admin.promptAudit.cleanup.estimatedBytes') }}</dt><dd>{{ formatBytes(preview.estimated_reclaimable_bytes) }}</dd>
          <dt>{{ t('admin.promptAudit.events.snapshotMax') }}</dt><dd>{{ preview.snapshot_max_id }}</dd>
          <dt>{{ t('admin.promptAudit.events.expiresAt') }}</dt><dd>{{ formatDate(preview.expires_at) }}</dd>
        </dl>
        <p class="mt-2 text-xs text-amber-800 dark:text-amber-200">{{ t('admin.promptAudit.cleanup.estimateHint') }}</p>
      </div>
      <p v-else class="rounded-lg border border-dashed border-gray-300 px-4 py-3 text-xs text-gray-500 dark:border-dark-600 dark:text-dark-400">
        {{ t('admin.promptAudit.cleanup.previewRequired') }}
      </p>
    </div>

    <template #footer>
      <div class="flex flex-wrap items-center justify-end gap-3">
        <button type="button" class="btn btn-secondary" @click="$emit('close')">{{ t('common.cancel') }}</button>
        <button type="button" class="btn btn-secondary" :disabled="!canPreview || previewing || deleting" data-test="preview-pass-cleanup" @click="requestPreview">
          {{ previewing ? t('admin.promptAudit.events.filterDeletePreviewing') : t('admin.promptAudit.events.filterDeletePreviewAction') }}
        </button>
        <button type="button" class="btn btn-danger" :disabled="!preview || preview.matched_count === 0 || deleting || previewing" data-test="confirm-pass-cleanup" @click="$emit('confirm')">
          {{ deleting ? t('common.submitting') : t('admin.promptAudit.cleanup.confirm') }}
        </button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import OpenAIFastPolicyUserSelector from '@/views/admin/settings/OpenAIFastPolicyUserSelector.vue'
import type { PromptDeletePreview, PromptEventFilters } from '../types'
import { DELETE_RANGE_PRESETS, passCleanupFilters, resolveDeleteRangeFilters, type DeleteRangePreset } from '../viewModel'

const props = defineProps<{ show: boolean; initialUserID?: number; preview: PromptDeletePreview | null; previewing: boolean; deleting: boolean }>()
const emit = defineEmits<{
  (event: 'close'): void
  (event: 'preview', filters: PromptEventFilters): void
  (event: 'confirm'): void
  (event: 'criteria-change'): void
}>()
const { t, locale } = useI18n()
const allUsers = ref(true)
const selectedUserIDs = ref<number[]>([])
const preset = ref<DeleteRangePreset>('7d')
const customStart = ref('')
const customEnd = ref('')

watch(() => props.show, (visible) => {
  if (!visible) return
  const userID = Number(props.initialUserID || 0)
  allUsers.value = userID <= 0
  selectedUserIDs.value = userID > 0 ? [userID] : []
  preset.value = '7d'
  customStart.value = ''
  customEnd.value = ''
}, { immediate: true })

const customRangeValid = computed(() => {
  if (preset.value !== 'custom') return true
  const start = new Date(customStart.value).getTime()
  const end = new Date(customEnd.value).getTime()
  return Number.isFinite(start) && Number.isFinite(end) && start < end
})
const canPreview = computed(() => (allUsers.value || selectedUserIDs.value.length === 1) && customRangeValid.value)

function selectOneUser(userIDs: number[]) {
  selectedUserIDs.value = userIDs.length ? [userIDs[userIDs.length - 1]] : []
  criteriaChanged()
}
function criteriaChanged() { emit('criteria-change') }
function requestPreview() {
  if (!canPreview.value) return
  const filters = passCleanupFilters(allUsers.value ? 0 : selectedUserIDs.value[0])
  if (preset.value === 'custom') {
    filters.start_at = customStart.value
    filters.end_at = customEnd.value
  }
  emit('preview', resolveDeleteRangeFilters(filters, preset.value))
}
function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index === 0 ? 0 : 2)} ${units[index]}`
}
function formatDate(value: string): string {
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value))
}
</script>
