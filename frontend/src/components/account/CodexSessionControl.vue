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
    <p class="text-xs text-gray-500">{{ t('admin.accounts.openai.sessionOverrideTestHint') }}</p>
    <p class="text-xs text-gray-500">{{ t('admin.accounts.openai.sessionOverrideReconnectHint') }}</p>
    <CodexTestStateControl :value="turn" :busy="locked || !config?.supported" @change="changeTurn" />
    <div class="flex items-center justify-end gap-2">
      <button v-if="error" type="button" class="text-sm text-red-600" :disabled="locked" @click="load">{{ t('common.retry') }}</button>
      <button type="button" class="btn btn-primary flex items-center gap-1.5" :disabled="locked || !config?.supported || !dirty || (enabled && !sessionID) || (turn.enabled && !turn.turn_state)" data-testid="codex-session-save" @click="save">
        <Icon name="check" size="sm" />{{ t('common.save') }}
      </button>
    </div>
    <p v-if="error" role="alert" class="break-words text-sm text-red-600">{{ error }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Icon } from '@/components/icons'
import { adminAPI } from '@/api/admin'
import type { CodexSessionConfiguration, CodexSessionOverride, CodexAccountTurnConfiguration, CodexTurnStateTestOverride } from '@/api/admin/accounts'
import CodexTestStateControl from './CodexTestStateControl.vue'
import type { Account } from '@/types'

const props = defineProps<{ account: Account; busy: boolean; captured?: CodexTurnStateTestOverride | null }>()
const emit = defineEmits<{ (e: 'draft', value: CodexSessionOverride | null): void; (e: 'turn-draft', value: CodexTurnStateTestOverride | null): void; (e: 'saved'): void; (e: 'pending', value: boolean): void }>()
const { t } = useI18n()
const config = ref<CodexSessionConfiguration | null>(null)
const enabled = ref(false)
const sessionID = ref('')
const emptyTurn = (): CodexAccountTurnConfiguration => ({ enabled: false, turn_id: '', turn_state: '', identity: '', revision: '', updated_at: '' })
const turn = ref<CodexAccountTurnConfiguration>(emptyTurn())
const loading = ref(false)
const saving = ref(false)
const error = ref('')
let generation = 0
const eligible = computed(() => props.account.platform === 'openai' && ['oauth', 'setup_token'].includes(String(props.account.type)) &&
  !props.account.parent_account_id && ['session', 'full'].includes(String(props.account.extra?.codex_fingerprint_mode)))
const dirty = computed(() => !!config.value && (enabled.value !== config.value.enabled || sessionID.value !== config.value.session_id || JSON.stringify(turn.value) !== JSON.stringify(config.value.account_turn || emptyTurn())))
const locked = computed(() => props.busy || loading.value || saving.value)

function changeDraft() {
  clearTurnState()
  if (enabled.value && !sessionID.value) randomize()
  else emit('draft', { enabled: enabled.value, session_id: sessionID.value })
}

function randomize() {
  // 草稿仅传给测试接口，明确保存前不改变正式转发身份。
  sessionID.value = crypto.randomUUID()
  enabled.value = true
  clearTurnState()
  emit('draft', { enabled: true, session_id: sessionID.value })
}

function changeTurn(value: CodexAccountTurnConfiguration) {
  turn.value = value
  emit('turn-draft', value.enabled
    ? { turn_id: value.turn_id, turn_state: value.turn_state, identity: value.identity }
    : { turn_id: '', turn_state: '', disabled: true })
}

function clearTurnState() {
  // session 改变后，旧响应签发的状态不能保存到新身份。
  changeTurn({ ...turn.value, turn_state: '', identity: '' })
}

watch(() => props.captured, value => {
  if (value?.turn_state && value.identity && turn.value.enabled && value.turn_id === turn.value.turn_id) {
    changeTurn({ ...turn.value, turn_state: value.turn_state, identity: value.identity })
  }
})

async function load() {
  const current = ++generation
  config.value = null
  error.value = ''
  enabled.value = false
  sessionID.value = ''
  turn.value = emptyTurn()
  emit('turn-draft', null)
  saving.value = false
  loading.value = false
  emit('draft', null)
  if (!eligible.value) return
  loading.value = true
  try {
    const value = await adminAPI.accounts.getCodexSession(props.account.id)
    if (current !== generation) return
    config.value = value
    enabled.value = value.enabled
    sessionID.value = value.session_id
    changeTurn({ ...(value.account_turn || emptyTurn()) })
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
    const value = await adminAPI.accounts.saveCodexSession(props.account.id, { enabled: enabled.value, session_id: sessionID.value, account_turn: { ...turn.value } })
    if (current !== generation) return
    config.value = value
    enabled.value = value.enabled
    sessionID.value = value.session_id
    changeTurn({ ...(value.account_turn || emptyTurn()) })
    emit('draft', null)
    emit('saved')
  } catch {
    if (current === generation) error.value = t('admin.accounts.openai.sessionOverrideSaveFailed')
  } finally {
    if (current === generation) saving.value = false
  }
}

// 配置请求期间禁止发起测试，避免保存与测试交错使用旧草稿。
watch([loading, saving], ([isLoading, isSaving]) => emit('pending', isLoading || isSaving), { immediate: true, flush: 'sync' })
watch(() => [props.account.id, props.account.type, props.account.extra?.codex_fingerprint_mode, eligible.value], load, { immediate: true })
onBeforeUnmount(() => {
  // 关闭弹框后忽略迟到的响应，重新打开时从数据库加载。
  generation++
  emit('draft', null)
  emit('turn-draft', null)
  emit('pending', false)
})
</script>
