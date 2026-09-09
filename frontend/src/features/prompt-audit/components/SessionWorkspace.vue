<template>
  <section class="py-6" data-test="session-workspace">
    <h2 class="text-base font-semibold">{{ t('admin.promptAudit.sessions.title') }}</h2>
    <p class="mt-2 text-sm text-gray-500">{{ t('admin.promptAudit.sessions.description') }}</p>
    <form class="my-4 flex flex-wrap items-end gap-3" @submit.prevent="search">
      <label class="text-sm">{{ t('admin.promptAudit.events.userId') }}
        <input v-model="userID" type="number" min="1" step="1" class="input mt-1" :disabled="loading" />
      </label>
      <button type="submit" class="btn btn-primary" :disabled="loading">{{ t('common.search') }}</button>
      <button v-if="selected" type="button" class="btn btn-secondary" :disabled="loading" @click="back">{{ t('admin.promptAudit.sessions.back') }}</button>
      <button v-if="selected" type="button" class="btn btn-secondary" :disabled="loading" data-test="manage-session" @click="$emit('manage', selected.id)">{{ t('admin.promptAudit.sessions.manage') }}</button>
    </form>
    <p v-if="error" role="alert" class="mb-4 text-sm text-red-600">{{ error }}</p>
    <p v-if="loading" role="status" class="py-8 text-gray-500">{{ t('common.loading') }}</p>
    <template v-else>
      <div class="overflow-x-auto">
        <table v-if="!selected" class="w-full min-w-[600px] text-left text-sm">
          <thead><tr class="border-b dark:border-dark-700"><th class="p-3">{{ t('admin.promptAudit.events.userId') }}</th><th class="p-3">{{ t('admin.promptAudit.analysis.session') }}</th><th class="p-3">{{ t('admin.promptAudit.sessions.counts') }}</th><th class="p-3">{{ t('admin.promptAudit.sessions.lastSeen') }}</th><th class="p-3">{{ t('common.actions') }}</th></tr></thead>
          <tbody><tr v-for="session in sessions" :key="session.id" class="border-b dark:border-dark-700">
            <td class="p-3">#{{ session.user_id }}</td>
            <td class="p-3"><span class="font-mono" :title="session.session_key">{{ session.session_key.slice(0, 16) }}…</span><p class="mt-1 text-xs text-gray-500">{{ session.session_source }}</p></td>
            <td class="p-3">{{ session.event_count }} / {{ session.risk_count }} / {{ session.evidence_count }}</td>
            <td class="whitespace-nowrap p-3">{{ new Date(session.last_seen_at).toLocaleString() }}</td>
            <td class="p-3"><button class="btn btn-secondary btn-sm" data-test="open-session" @click="open(session)">{{ t('admin.promptAudit.sessions.open') }}</button></td>
          </tr></tbody>
        </table>
        <table v-else class="w-full min-w-[480px] text-left text-sm">
          <caption class="pb-3 text-left">#{{ selected.user_id }} · {{ selected.session_key.slice(0, 16) }}…</caption>
          <thead><tr class="border-b dark:border-dark-700"><th class="p-3">{{ t('admin.promptAudit.events.decision') }}</th><th class="p-3">{{ t('admin.promptAudit.events.model') }}</th><th class="p-3">{{ t('admin.promptAudit.sessions.evidence') }}</th><th class="p-3">{{ t('common.actions') }}</th></tr></thead>
          <tbody><tr v-for="event in events" :key="event.id" class="border-b dark:border-dark-700">
            <td class="p-3">{{ t(`admin.promptAudit.decisions.${event.decision}`) }}<p class="mt-1 text-xs text-gray-500">{{ new Date(event.created_at).toLocaleString() }}</p></td>
            <td class="p-3">{{ event.snapshot.model }}</td>
            <td class="p-3">{{ t(event.full_context_available ? 'admin.promptAudit.sessions.available' : 'admin.promptAudit.sessions.unavailable') }}</td>
            <td class="p-3"><button class="btn btn-secondary btn-sm" data-test="view-evidence" @click="$emit('view', event.id)">{{ t('admin.promptAudit.sessions.view') }}</button></td>
          </tr></tbody>
        </table>
      </div>
      <p v-if="!(selected ? events.length : sessions.length)" class="py-8 text-center text-gray-500">{{ t('admin.promptAudit.sessions.empty') }}</p>
      <div class="mt-4 flex items-center justify-end gap-3">
        <button class="btn btn-secondary btn-sm" :disabled="page <= 1" @click="changePage(-1)">{{ t('admin.promptAudit.sessions.previous') }}</button>
        <span class="text-sm">{{ page }} / {{ Math.max(1, Math.ceil(total / 20)) }}</span>
        <button class="btn btn-secondary btn-sm" :disabled="page * 20 >= total" @click="changePage(1)">{{ t('admin.promptAudit.sessions.next') }}</button>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { listSessions, listSessionEvents, type PromptSession } from '../api'
import type { PromptAuditEvent } from '../types'
import { extractApiErrorMessage } from '@/utils/apiError'

defineEmits<{ view: [id: number]; manage: [id: number] }>()
const { t } = useI18n()
const userID = ref('')
const page = ref(1)
const total = ref(0)
const loading = ref(false)
const error = ref('')
const sessions = ref<PromptSession[]>([])
const events = ref<PromptAuditEvent[]>([])
const selected = ref<PromptSession | null>(null)
let generation = 0

// 离开标签页或快速切换时丢弃旧响应，避免显示前一个用户或会话的数据。
async function load() {
  const current = ++generation
  loading.value = true
  error.value = ''
  try {
    if (selected.value) {
      const result = await listSessionEvents(selected.value.id, page.value)
      if (current !== generation) return
      events.value = result.items || []
      total.value = result.total
    } else {
      const result = await listSessions(page.value, userID.value ? Number(userID.value) : undefined)
      if (current !== generation) return
      sessions.value = result.items || []
      total.value = result.total
    }
  } catch (err) {
    if (current !== generation) return
    sessions.value = []; events.value = []; total.value = 0
    error.value = extractApiErrorMessage(err, t('admin.promptAudit.sessions.loadFailed'))
  } finally {
    if (current === generation) loading.value = false
  }
}
function search() { selected.value = null; page.value = 1; void load() }
function open(session: PromptSession) { selected.value = session; page.value = 1; void load() }
function back() { selected.value = null; page.value = 1; void load() }
function changePage(delta: number) { page.value += delta; void load() }
onMounted(load)
onUnmounted(() => { generation++ })
</script>
