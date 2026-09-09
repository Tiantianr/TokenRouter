<template>
  <AppLayout>
    <div class="mx-auto max-w-[1600px]" :class="activeTab === 'config' && draft ? 'pb-28' : 'pb-8'">
      <header class="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.16em] text-primary-600 dark:text-primary-400">{{ t('nav.securityAudit') }}</p>
          <h1 class="mt-1 text-2xl font-semibold tracking-tight text-gray-950 dark:text-white">{{ t('admin.promptAudit.title') }}</h1>
          <p class="mt-2 max-w-3xl text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.description') }}</p>
        </div>
        <div v-if="draft" class="text-right text-xs text-gray-500 dark:text-dark-400">
          <p>{{ t('admin.promptAudit.configVersion', { version: draft.config_version }) }}</p>
          <p v-if="draft.updated_at" class="mt-1">{{ formatDate(draft.updated_at) }}</p>
        </div>
      </header>

      <div v-if="loadErrors.config && !draft" role="alert" class="rounded-xl border border-red-200 bg-red-50 p-5 dark:border-red-900 dark:bg-red-950/30">
        <p class="text-sm text-red-700 dark:text-red-300">{{ loadErrors.config }}</p>
        <button type="button" class="btn btn-secondary btn-sm mt-3" @click="loadConfig">{{ t('admin.promptAudit.actions.retry') }}</button>
      </div>

      <!-- 配置加载失败不应隐藏已有事件和会话证据的查询入口。 -->
      <div>
        <div class="mb-4" role="tablist" :aria-label="t('admin.promptAudit.title')">
          <div class="tabs inline-flex">
            <button
              v-for="tab in pageTabs"
              :key="tab.id"
              type="button"
              role="tab"
              class="tab"
              :class="{ 'tab-active': activeTab === tab.id }"
              :aria-selected="activeTab === tab.id"
              :data-test="`tab-${tab.id}`"
              @click="activeTab = tab.id"
            >
              {{ tab.label }}
            </button>
          </div>
        </div>

        <main class="card px-4 sm:px-6 lg:px-8">
          <SessionWorkspace v-if="activeTab === 'sessions'" @view="openEvent" @manage="manageSession" />
          <div v-show="activeTab === 'config'" data-test="tab-panel-config">
            <RuntimeOverview :runtime="runtime" :loading="loading.runtime" :error="loadErrors.runtime" @refresh="loadRuntime" />

            <template v-if="draft">
              <EndpointPool
                :endpoints="draft.endpoints"
                :probe-results="probeResults"
                :probing-ids="probingIds"
                @update:endpoints="updateEndpoints"
                @probe="runProbe"
              />
              <div v-if="loadErrors.groups" role="alert" class="mt-5 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">{{ loadErrors.groups }}</div>
              <PolicyPanel :draft="draft" :groups="groups" @update:draft="replaceDraft" />
              <PassRetentionPanel
                :config="passRetention"
                :user-ids="retentionUserIDs"
                :dirty="retentionDirty"
                :loading="loading.retention"
                :saving="loading.savingRetention"
                :error="loadErrors.retention"
                @update:user-ids="retentionUserIDs = canonicalUserIDs($event)"
                @save="savePassRetention"
                @reset="resetPassRetention"
              />
            </template>
          </div>

          <div v-show="activeTab === 'events'" data-test="tab-panel-events">
            <div
              v-if="draft?.enabled && passRetention"
              data-test="pass-events-disabled-notice"
              role="status"
              class="mt-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-900/70 dark:bg-amber-950/30 dark:text-amber-200"
            >
              <span>{{ t('admin.promptAudit.events.passRetentionNotice', { count: passRetention.user_ids?.length || 0 }) }}</span>
              <button type="button" class="btn btn-secondary btn-sm" @click="activeTab = 'config'">
                {{ t('admin.promptAudit.events.openConfiguration') }}
              </button>
            </div>
            <EventWorkspace
              :events="events.items"
              :total="events.total"
              :page="events.page"
              :page-size="events.page_size"
              :filters="filters"
              :selected-ids="selectedEventIds"
              :loading="loading.events"
              :error="loadErrors.events"
              @filters-change="handleFiltersChanged"
              @search="applyEventFilters"
              @selection="selectedEventIds = $event"
              @page="changePage"
              @page-size="changePageSize"
              @view="openEvent"
              @analyze="analyzeEvent"
              @delete="requestSingleDelete"
              @batch-delete="requestBatchDelete"
              @preview-delete="requestFilterDeletePreview"
              @cleanup-pass="openPassCleanup"
            />
          </div>
        </main>
      </div>
    </div>

    <div v-if="draft && activeTab === 'config'" class="fixed inset-x-0 bottom-0 z-30 border-t border-gray-200 bg-white/95 px-4 py-3 shadow-[0_-12px_35px_rgba(15,23,42,0.08)] backdrop-blur dark:border-dark-700/80 dark:bg-dark-900/95 dark:shadow-[0_-12px_35px_rgba(0,0,0,0.35)] lg:left-64">
      <div class="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap items-center gap-x-5 gap-y-2">
          <SaveToggle :label="t('admin.promptAudit.saveBar.enabled')" :model-value="draft.enabled" data-test="enabled-toggle" @update:model-value="setEnabled" />
          <SaveToggle :label="t('admin.promptAudit.saveBar.blocking')" :model-value="draft.blocking_enabled" :disabled="!draft.enabled" data-test="blocking-toggle" @update:model-value="setBlocking" />
        </div>
        <div class="flex items-center gap-3">
          <span class="text-sm" :class="dirty ? 'text-amber-700 dark:text-amber-300' : 'text-gray-500 dark:text-dark-400'">
            {{ dirty ? t('admin.promptAudit.saveBar.dirty') : t('admin.promptAudit.saveBar.synced') }}
          </span>
          <button type="button" class="btn btn-secondary" :disabled="!dirty || loading.saving" @click="resetDraft">{{ t('common.reset') }}</button>
          <button type="button" class="btn btn-primary" :disabled="!dirty || loading.saving" data-test="save-config" @click="saveConfig">
            {{ loading.saving ? t('common.saving') : t('common.save') }}
          </button>
        </div>
      </div>
    </div>

    <ConfirmDialog
      :show="showBlockingConfirmation"
      :title="t('admin.promptAudit.blockingConfirm.title')"
      :message="t('admin.promptAudit.blockingConfirm.message')"
      :confirm-text="t('admin.promptAudit.blockingConfirm.confirm')"
      danger
      @confirm="confirmBlocking"
      @cancel="showBlockingConfirmation = false"
    />
    <ConfirmDialog
      :show="deleteRequest.mode !== ''"
      :title="t('admin.promptAudit.events.deleteConfirmTitle')"
      :message="t('admin.promptAudit.events.deleteConfirmMessage', { count: deleteRequest.ids.length })"
      :confirm-text="t('common.delete')"
      danger
      @confirm="confirmIDDelete"
      @cancel="clearDeleteRequest"
    />
    <FilterDeleteDialog
      :show="showFilterDelete"
      :initial-filters="filters"
      :preview="deletePreview"
      :previewing="loading.previewing"
      :deleting="loading.deleting"
      @close="closeFilterDelete"
      @preview="runFilterDeletePreview"
      @confirm="confirmFilterDelete"
      @criteria-change="clearDeletePreview"
    />
    <PassEventCleanupDialog
      :show="showPassCleanup"
      :preview="passCleanupPreview"
      :previewing="loading.previewing"
      :deleting="loading.deleting"
      @close="closePassCleanup"
      @preview="runPassCleanupPreview"
      @confirm="confirmPassCleanup"
      @criteria-change="clearPassCleanupPreview"
    />
    <EventDetailDialog :show="showEventDetail" :event="activeEvent" :loading="loading.detail" @close="closeEventDetail" />
    <UserAnalysisDialog :show="showUserAnalysis" :analysis="userAnalysis" :loading="analyzingUser" :error="userAnalysisError" @close="closeUserAnalysis" />
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import SessionWorkspace from './components/SessionWorkspace.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAppStore } from '@/stores/app'
import { extractApiErrorCode, extractApiErrorMessage } from '@/utils/apiError'
import RuntimeOverview from './components/RuntimeOverview.vue'
import EndpointPool from './components/EndpointPool.vue'
import PolicyPanel from './components/PolicyPanel.vue'
import EventWorkspace from './components/EventWorkspace.vue'
import EventDetailDialog from './components/EventDetailDialog.vue'
import UserAnalysisDialog from './components/UserAnalysisDialog.vue'
import FilterDeleteDialog from './components/FilterDeleteDialog.vue'
import PassRetentionPanel from './components/PassRetentionPanel.vue'
import PassEventCleanupDialog from './components/PassEventCleanupDialog.vue'
import promptAuditAPI from './api'
import type {
  PromptAuditDraft,
  PromptAuditEndpointDraft,
  PromptAuditEvent,
  PromptAuditGroup,
  PromptAuditRuntime,
  PromptDeletePreview,
  PromptEventFilters,
  PromptEventPage,
  PromptLoadErrors,
  PromptProbeResult,
  PromptPassRetentionConfig,
  PromptUserAnalysis,
} from './types'
import { buildUpdateRequest, cloneData, configToDraft, draftFingerprint, emptyEventFilters } from './viewModel'

const { t, locale } = useI18n()
const appStore = useAppStore()
type PromptAuditPageTab = 'config' | 'events' | 'sessions'
const activeTab = ref<PromptAuditPageTab>('events')
const pageTabs = computed(() => [
  { id: 'events' as const, label: t('admin.promptAudit.tabs.events') },
  { id: 'sessions' as const, label: t('admin.promptAudit.sessions.title') },
  { id: 'config' as const, label: t('admin.promptAudit.tabs.config') },
])
const serverConfig = ref<PromptAuditDraft | null>(null)
const draft = ref<PromptAuditDraft | null>(null)
const passRetention = ref<PromptPassRetentionConfig | null>(null)
const retentionUserIDs = ref<number[]>([])
const runtime = ref<PromptAuditRuntime | null>(null)
const groups = ref<PromptAuditGroup[]>([])
const events = reactive<PromptEventPage>({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
const filters = ref<PromptEventFilters>(emptyEventFilters())
const appliedFilters = ref<PromptEventFilters>(emptyEventFilters())
const selectedEventIds = ref<number[]>([])
const activeEvent = ref<PromptAuditEvent | null>(null)
const showEventDetail = ref(false)
const showUserAnalysis = ref(false)
const userAnalysis = ref<PromptUserAnalysis | null>(null)
const userAnalysisError = ref('')
const analyzingUser = ref(false)
let userAnalysisRequestToken = 0
const probeResults = reactive<Record<string, PromptProbeResult>>({})
const probingIds = ref<string[]>([])
const showFilterDelete = ref(false)
const showPassCleanup = ref(false)
const passCleanupPreview = ref<PromptDeletePreview | null>(null)
const passCleanupFilters = ref<PromptEventFilters | null>(null)
const deletePreview = ref<PromptDeletePreview | null>(null)
const deletePreviewFilters = ref<PromptEventFilters | null>(null)
const showBlockingConfirmation = ref(false)
const deleteRequest = reactive<{ mode: '' | 'single' | 'batch'; ids: number[] }>({ mode: '', ids: [] })
const loading = reactive({ config: false, retention: false, runtime: false, groups: false, events: false, saving: false, savingRetention: false, detail: false, deleting: false, previewing: false })
const loadErrors = reactive<PromptLoadErrors>({ config: '', retention: '', runtime: '', groups: '', events: '' })
const dirty = computed(() => draftFingerprint(draft.value) !== draftFingerprint(serverConfig.value))
const retentionDirty = computed(() => JSON.stringify(canonicalUserIDs(retentionUserIDs.value)) !== JSON.stringify(passRetention.value?.user_ids || []))

const SaveToggle = defineComponent({
  inheritAttrs: false,
  props: { label: { type: String, required: true }, modelValue: { type: Boolean, required: true }, disabled: { type: Boolean, default: false } },
  emits: ['update:modelValue'],
  setup(props, { emit, attrs }) {
    return () => h('label', { class: ['flex items-center gap-2.5 text-sm', props.disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'] }, [
      h('button', {
        ...attrs,
        type: 'button',
        role: 'switch',
        'aria-checked': props.modelValue,
        'aria-label': props.label,
        disabled: props.disabled,
        class: [
          'relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:ring-offset-2',
          props.modelValue ? 'bg-primary-600' : 'bg-gray-300 dark:bg-dark-600',
          props.disabled ? 'cursor-not-allowed' : 'cursor-pointer',
        ],
        onClick: (event: MouseEvent) => {
          event.preventDefault()
          if (!props.disabled) emit('update:modelValue', !props.modelValue)
        },
      }, [
        h('span', {
          class: [
            'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform duration-200 ease-in-out',
            props.modelValue ? 'translate-x-5' : 'translate-x-0',
          ],
        }),
      ]),
      h('span', { class: 'select-none text-gray-700 dark:text-dark-200' }, props.label),
    ])
  },
})

function errorMessage(error: unknown, fallbackKey: string): string {
  const code = extractApiErrorCode(error)
  if (code) {
    const key = `admin.promptAudit.errors.${code}`
    const translated = t(key)
    if (translated !== key) return translated
  }
  return extractApiErrorMessage(error, t(fallbackKey))
}

async function loadConfig() {
  loading.config = true
  loadErrors.config = ''
  try {
    const config = await promptAuditAPI.getConfig()
    serverConfig.value = configToDraft(config)
    draft.value = configToDraft(config)
  } catch (error) {
    loadErrors.config = errorMessage(error, 'admin.promptAudit.errors.loadConfig')
  } finally {
    loading.config = false
  }
}
async function loadRuntime() {
  loading.runtime = true
  loadErrors.runtime = ''
  try { runtime.value = await promptAuditAPI.getRuntime() }
  catch (error) { loadErrors.runtime = errorMessage(error, 'admin.promptAudit.errors.loadRuntime') }
  finally { loading.runtime = false }
}
async function loadPassRetention() {
  loading.retention = true
  loadErrors.retention = ''
  try {
    const loaded = await promptAuditAPI.getPassRetention()
    const userIDs = canonicalUserIDs(loaded?.user_ids)
    passRetention.value = { ...loaded, user_ids: userIDs }
    retentionUserIDs.value = userIDs
  } catch (error) {
    loadErrors.retention = errorMessage(error, 'admin.promptAudit.errors.loadRetention')
  } finally { loading.retention = false }
}
async function loadGroups() {
  loading.groups = true
  loadErrors.groups = ''
  try { groups.value = await promptAuditAPI.listGroups() }
  catch (error) { loadErrors.groups = errorMessage(error, 'admin.promptAudit.errors.loadGroups') }
  finally { loading.groups = false }
}
async function loadEvents() {
  loading.events = true
  loadErrors.events = ''
  try {
    const result = await promptAuditAPI.listEvents(appliedFilters.value, events.page, events.page_size)
    Object.assign(events, result)
    selectedEventIds.value = []
  } catch (error) {
    loadErrors.events = errorMessage(error, 'admin.promptAudit.errors.loadEvents')
  } finally {
    loading.events = false
  }
}
async function loadInitial() {
  await Promise.allSettled([loadConfig(), loadPassRetention(), loadRuntime(), loadGroups(), loadEvents()])
}

function canonicalUserIDs(values: number[] | null | undefined): number[] {
  return [...new Set((values || []).filter((value) => Number.isInteger(value) && value > 0))].sort((a, b) => a - b)
}
function resetPassRetention() { retentionUserIDs.value = [...(passRetention.value?.user_ids || [])] }
async function savePassRetention() {
  if (!passRetention.value || !retentionDirty.value) return
  loading.savingRetention = true
  try {
    const saved = await promptAuditAPI.updatePassRetention({
      expected_revision: passRetention.value.revision,
      user_ids: canonicalUserIDs(retentionUserIDs.value),
    })
    const userIDs = canonicalUserIDs(saved?.user_ids)
    passRetention.value = { ...saved, user_ids: userIDs }
    retentionUserIDs.value = userIDs
    appStore.showSuccess(t('admin.promptAudit.messages.retentionSaved'))
  } catch (error) {
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.saveRetention'))
  } finally { loading.savingRetention = false }
}

function replaceDraft(value: PromptAuditDraft) { draft.value = cloneData(value) }
function updateEndpoints(value: PromptAuditEndpointDraft[]) {
  if (!draft.value) return
  replaceDraft({ ...draft.value, endpoints: value })
}
function setEnabled(value: boolean) {
  if (!draft.value) return
  replaceDraft({
    ...draft.value,
    enabled: value,
    blocking_enabled: value ? draft.value.blocking_enabled : false,
  })
}
function setBlocking(value: boolean) {
  if (!draft.value || !draft.value.enabled) return
  if (value && !draft.value.blocking_enabled) { showBlockingConfirmation.value = true; return }
  replaceDraft({ ...draft.value, blocking_enabled: value })
}
function confirmBlocking() {
  showBlockingConfirmation.value = false
  if (draft.value) replaceDraft({ ...draft.value, blocking_enabled: true })
}
function resetDraft() {
  if (serverConfig.value) draft.value = cloneData(serverConfig.value)
}
async function saveConfig() {
  if (!draft.value || !dirty.value) return
  loading.saving = true
  try {
    const saved = await promptAuditAPI.updateConfig(buildUpdateRequest(draft.value))
    serverConfig.value = configToDraft(saved)
    draft.value = configToDraft(saved)
    appStore.showSuccess(t('admin.promptAudit.messages.saved'))
    await loadRuntime()
  } catch (error) {
    const code = extractApiErrorCode(error)
    appStore.showError(errorMessage(error, code === 'prompt_audit_config_conflict' ? 'admin.promptAudit.errors.prompt_audit_config_conflict' : 'admin.promptAudit.errors.saveConfig'))
  } finally {
    loading.saving = false
  }
}
async function runProbe(endpoint: PromptAuditEndpointDraft) {
  if (probingIds.value.includes(endpoint.id)) return
  probingIds.value = [...probingIds.value, endpoint.id]
  try {
    const result = await promptAuditAPI.probeEndpoint(endpoint)
    probeResults[endpoint.id] = result
    if (result.ok) appStore.showSuccess(t('admin.promptAudit.messages.probeSucceeded'))
    else appStore.showError(`${result.error_code || result.status}: ${result.message}`)
  } catch (error) {
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.probe'))
  } finally {
    probingIds.value = probingIds.value.filter((id) => id !== endpoint.id)
  }
}

function handleFiltersChanged(value: PromptEventFilters) {
  filters.value = cloneData(value)
  clearDeletePreview()
}

// 从会话进入事件管理时保留精确范围，批量删除预览也使用同一会话过滤条件。
function manageSession(id: number) {
  activeTab.value = 'events'
  applyEventFilters({ ...emptyEventFilters(), session_id: String(id) })
}
function applyEventFilters(value: PromptEventFilters) {
  filters.value = cloneData(value)
  appliedFilters.value = cloneData(value)
  events.page = 1
  clearDeletePreview()
  void loadEvents()
}
function changePage(value: number) { events.page = value; void loadEvents() }
function changePageSize(value: number) { events.page_size = value; events.page = 1; void loadEvents() }
async function openEvent(id: number) {
  showEventDetail.value = true
  loading.detail = true
  activeEvent.value = null
  try { activeEvent.value = await promptAuditAPI.getEvent(id) }
  catch (error) { appStore.showError(errorMessage(error, 'admin.promptAudit.errors.loadDetail')); showEventDetail.value = false }
  finally { loading.detail = false }
}
function closeEventDetail() { showEventDetail.value = false; activeEvent.value = null }
async function analyzeEvent(id: number) {
  const requestToken = ++userAnalysisRequestToken
  showUserAnalysis.value = true
  analyzingUser.value = true
  userAnalysis.value = null
  userAnalysisError.value = ''
  try {
    const result = await promptAuditAPI.analyzeEvent(id)
    if (requestToken === userAnalysisRequestToken) userAnalysis.value = result
  } catch (error) {
    if (requestToken === userAnalysisRequestToken) {
      userAnalysisError.value = errorMessage(error, 'admin.promptAudit.errors.analyzeEvent')
    }
  } finally {
    if (requestToken === userAnalysisRequestToken) analyzingUser.value = false
  }
}
function closeUserAnalysis() {
  userAnalysisRequestToken++
  showUserAnalysis.value = false
  userAnalysis.value = null
  userAnalysisError.value = ''
}
function requestSingleDelete(id: number) { deleteRequest.mode = 'single'; deleteRequest.ids = [id] }
function requestBatchDelete() { if (selectedEventIds.value.length) { deleteRequest.mode = 'batch'; deleteRequest.ids = [...selectedEventIds.value] } }
function clearDeleteRequest() { deleteRequest.mode = ''; deleteRequest.ids = [] }
async function confirmIDDelete() {
  const mode = deleteRequest.mode
  const ids = [...deleteRequest.ids]
  clearDeleteRequest()
  if (!mode || ids.length === 0) return
  loading.deleting = true
  try {
    const result = mode === 'single' ? await promptAuditAPI.deleteEvent(ids[0]) : await promptAuditAPI.batchDeleteEvents(ids)
    appStore.showSuccess(t('admin.promptAudit.messages.deleted', { count: result.deleted_events }))
    await Promise.allSettled([loadEvents(), loadRuntime()])
  } catch (error) { appStore.showError(errorMessage(error, 'admin.promptAudit.errors.delete')) }
  finally { loading.deleting = false }
}
function clearDeletePreview() {
  deletePreview.value = null
  deletePreviewFilters.value = null
}
function requestFilterDeletePreview() {
  clearDeletePreview()
  showFilterDelete.value = true
}
function closeFilterDelete() {
  showFilterDelete.value = false
  clearDeletePreview()
}
async function runFilterDeletePreview(value: PromptEventFilters) {
  loading.previewing = true
  try {
    deletePreview.value = await promptAuditAPI.previewDelete(value)
    deletePreviewFilters.value = cloneData(value)
  } catch (error) {
    clearDeletePreview()
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.previewDelete'))
  } finally { loading.previewing = false }
}
async function confirmFilterDelete(filters?: PromptEventFilters) {
  if (loading.deleting) return
  loading.deleting = true
  try {
    let preview = deletePreview.value
    let previewFilters = deletePreviewFilters.value ? cloneData(deletePreviewFilters.value) : null
    // One-click path: no fresh preview (never requested, or cleared by a
    // criteria change) — mint the confirmation token on the fly from the
    // criteria the dialog just emitted, then delete in the same action.
    if ((!preview || !previewFilters) && filters) {
      preview = await promptAuditAPI.previewDelete(filters)
      previewFilters = cloneData(filters)
    }
    if (!preview || !previewFilters) return
    const result = await promptAuditAPI.deleteEventsByFilter(previewFilters, preview)
    closeFilterDelete()
    appStore.showSuccess(t('admin.promptAudit.messages.deleted', { count: result.deleted_events }))
    await Promise.allSettled([loadEvents(), loadRuntime()])
  } catch (error) {
    clearDeletePreview()
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.deleteConfirmation'))
  } finally { loading.deleting = false }
}
function openPassCleanup() {
  clearPassCleanupPreview()
  showPassCleanup.value = true
}
function closePassCleanup() {
  showPassCleanup.value = false
  clearPassCleanupPreview()
}
function clearPassCleanupPreview() {
  passCleanupPreview.value = null
  passCleanupFilters.value = null
}
async function runPassCleanupPreview(value: PromptEventFilters) {
  loading.previewing = true
  try {
    const filters = { ...cloneData(value), decision: 'pass' }
    passCleanupPreview.value = await promptAuditAPI.previewDelete(filters)
    passCleanupFilters.value = filters
  } catch (error) {
    clearPassCleanupPreview()
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.previewDelete'))
  } finally { loading.previewing = false }
}
async function confirmPassCleanup() {
  if (!passCleanupPreview.value || !passCleanupFilters.value || loading.deleting) return
  loading.deleting = true
  try {
    const result = await promptAuditAPI.deleteEventsByFilter(passCleanupFilters.value, passCleanupPreview.value)
    closePassCleanup()
    appStore.showSuccess(t('admin.promptAudit.messages.deleted', { count: result.deleted_events }))
    await Promise.allSettled([loadEvents(), loadRuntime()])
  } catch (error) {
    clearPassCleanupPreview()
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.deleteConfirmation'))
  } finally { loading.deleting = false }
}
function formatDate(value: string): string {
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value))
}

onMounted(loadInitial)
</script>
