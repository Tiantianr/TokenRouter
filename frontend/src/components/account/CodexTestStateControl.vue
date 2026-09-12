<template>
  <div class="space-y-2 border-t border-gray-200 pt-3 dark:border-dark-500" data-testid="codex-test-state-control">
    <label class="flex items-center gap-2 text-sm font-medium">
      <input :checked="value.enabled" type="checkbox" :disabled="busy" data-testid="codex-test-state-enabled" @change="toggle" />
      {{ t('admin.accounts.openai.testTurnStateEnabled') }}
    </label>
    <template v-if="value.enabled">
      <div class="flex items-center gap-2">
        <input :value="value.turn_id" readonly class="input min-w-0 flex-1 font-mono text-xs" :aria-label="t('admin.accounts.openai.testTurnID')" data-testid="codex-test-turn-id" />
        <button type="button" class="btn btn-secondary shrink-0 p-2" :disabled="busy" :title="t('admin.accounts.openai.testTurnIDRandom')" :aria-label="t('admin.accounts.openai.testTurnIDRandom')" data-testid="codex-test-turn-id-random" @click="randomize">
          <Icon name="refresh" size="sm" />
        </button>
      </div>
      <p class="text-xs text-gray-500" data-testid="codex-turn-state-status">{{ t(value.turn_state ? 'admin.accounts.openai.testTurnStateCaptured' : 'admin.accounts.openai.testTurnStateWaiting') }}</p>
    </template>
    <p v-if="value.updated_at" class="text-xs text-gray-500">{{ t('admin.accounts.openai.testTurnStateUpdated', { time: value.updated_at }) }}</p>
    <p class="text-xs text-gray-500">{{ t('admin.accounts.openai.testTurnStateHint') }}</p>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { Icon } from '@/components/icons'
import type { CodexAccountTurnConfiguration } from '@/api/admin/accounts'

const props = defineProps<{ value: CodexAccountTurnConfiguration; busy: boolean }>()
const emit = defineEmits<{ (e: 'change', value: CodexAccountTurnConfiguration): void }>()
const { t } = useI18n()

function randomize() {
  // 新回合不继承旧状态；版本号保留用于保存时检查并发修改。
  emit('change', { ...props.value, enabled: true, turn_id: crypto.randomUUID(), turn_state: '', identity: '' })
}

function toggle() {
  if (props.value.enabled) emit('change', { ...props.value, enabled: false, turn_state: '', identity: '' })
  else randomize()
}
</script>
