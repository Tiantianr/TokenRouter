<template>
  <div v-if="eligible" class="space-y-2 border-y border-gray-200 py-3 dark:border-dark-500" data-testid="codex-session-control">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <label class="flex items-center gap-2 text-sm font-medium">
        <input v-model="enabled" type="checkbox" :disabled="locked || !config?.supported" data-testid="codex-session-enabled" @change="changeDraft" />
        {{ t('admin.accounts.openai.sessionOverrideEnabled') }}
      </label>
      <span class="text-xs text-gray-500">{{ t(dirty ? 'admin.accounts.openai.sessionOverrideDraft' : 'admin.accounts.openai.sessionOverrideSaved') }}</span>
    </div>
    <div v-if="enabled" class="flex items-center gap-2">
      <input :value="sessionID" readonly class="input min-w-0 flex-1 font-mono text-xs" :aria-label="t('admin.accounts.openai.sessionOverrideID')" data-testid="codex-session-id" />
      <button type="button" class="btn btn-secondary shrink-0 p-2" :disabled="locked" :title="t('admin.accounts.openai.sessionOverrideRandom')" :aria-label="t('admin.accounts.openai.sessionOverrideRandom')" data-testid="codex-session-random" @click="randomize">
        <Icon name="refresh" size="sm" />
      </button>
    </div>
    <div v-if="config?.effective_session_id" class="break-all font-mono text-xs text-gray-500">
      {{ t('admin.accounts.openai.sessionOverrideCurrent') }}: {{ config.effective_session_id }}
    </div>
    <div class="flex items-center justify-end gap-2">
      <button v-if="error" type="button" class="text-sm text-red-600" :disabled="locked" @click="load">{{ t('common.retry') }}</button>
      <button type="button" class="btn btn-primary flex items-center gap-1.5" :disabled="locked || !config?.supported || !dirty || (enabled && !sessionID)" data-testid="codex-session-save" @click="save">
        <Icon name="check" size="sm" />{{ t('common.save') }}
      </button>
    </div>
    <p v-if="error" role="alert" class="break-words text-sm text-red-600">{{ error }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Icon } from '@/components/icons'
import { adminAPI } from '@/api/admin'
import type { CodexSessionConfiguration, CodexSessionOverride } from '@/api/admin/accounts'
import type { Account } from '@/types'

const props = defineProps<{ account: Account; busy: boolean }>()
const emit = defineEmits<{ (e: 'draft', value: CodexSessionOverride | null): void; (e: 'saved'): void }>()
const { t } = useI18n()
const config = ref<CodexSessionConfiguration | null>(null)
const enabled = ref(false)
const sessionID = ref('')
const loading = ref(false)
const saving = ref(false)
const error = ref('')
let generation = 0
const eligible = computed(() => props.account.platform === 'openai' && ['oauth', 'setup_token'].includes(String(props.account.type)) &&
  !props.account.parent_account_id && ['session', 'full'].includes(String(props.account.extra?.codex_fingerprint_mode)))
const dirty = computed(() => !!config.value && (enabled.value !== config.value.enabled || sessionID.value !== config.value.session_id))
const locked = computed(() => props.busy || loading.value || saving.value)

function changeDraft() {
  if (enabled.value && !sessionID.value) randomize()
  else emit('draft', { enabled: enabled.value, session_id: sessionID.value })
}

function randomize() {
  // 草稿仅传给测试接口，明确保存前不改变正式转发身份。
  sessionID.value = crypto.randomUUID()
  enabled.value = true
  emit('draft', { enabled: true, session_id: sessionID.value })
}

async function load() {
  const current = ++generation
  config.value = null
  error.value = ''
  emit('draft', null)
  if (!eligible.value) return
  loading.value = true
  try {
    const value = await adminAPI.accounts.getCodexSession(props.account.id)
    if (current !== generation) return
    config.value = value
    enabled.value = value.enabled
    sessionID.value = value.session_id
  } catch {
    if (current === generation) error.value = t('admin.accounts.openai.sessionOverrideLoadFailed')
  } finally {
    if (current === generation) loading.value = false
  }
}

async function save() {
  const current = generation
  saving.value = true
  error.value = ''
  try {
    const value = await adminAPI.accounts.saveCodexSession(props.account.id, { enabled: enabled.value, session_id: sessionID.value })
    if (current !== generation) return
    config.value = value
    enabled.value = value.enabled
    sessionID.value = value.session_id
    emit('draft', null)
    emit('saved')
  } catch {
    if (current === generation) error.value = t('admin.accounts.openai.sessionOverrideSaveFailed')
  } finally {
    if (current === generation) saving.value = false
  }
}

watch(() => [props.account.id, eligible.value], load, { immediate: true })
</script>
