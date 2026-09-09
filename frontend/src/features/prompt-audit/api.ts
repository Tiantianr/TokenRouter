import { apiClient } from '@/api/client'
import type {
  PromptAuditConfig,
  PromptAuditEvent,
  PromptAuditGroup,
  PromptAuditRuntime,
  PromptAuditUpdateRequest,
  PromptDeletePreview,
  PromptDeleteResult,
  PromptEventFilters,
  PromptEventPage,
  PromptProbeResult,
  PromptAuditEndpointDraft,
  PromptPassRetentionConfig,
  PromptPassRetentionUpdateRequest,
  PromptUserAnalysis,
} from './types'
import { eventFilterPayload, eventQueryParams } from './viewModel'

const basePath = '/admin/prompt-audit'

// 会话列表仅含元数据，完整内容通过已有的事件详情和下载鉴权链路读取。
export interface PromptSession {
  id: number
  user_id: number
  session_key: string
  session_source: string
  last_seen_at: string
  event_count: number
  risk_count: number
  evidence_count: number
}

export async function listSessions(page: number, userID?: number) {
  const { data } = await apiClient.get<{ items: PromptSession[]; total: number; page: number; page_size: number }>(`${basePath}/sessions`, {
    params: { page, page_size: 20, user_id: userID }
  })
  return data
}

export async function listSessionEvents(sessionID: number, page: number): Promise<PromptEventPage> {
  const { data } = await apiClient.get<PromptEventPage>(`${basePath}/events`, {
    params: { session_id: sessionID, page, page_size: 20 }
  })
  return data
}

function normalizePassRetention(config: PromptPassRetentionConfig): PromptPassRetentionConfig {
  return { ...config, user_ids: Array.isArray(config.user_ids) ? config.user_ids : [] }
}

export async function getConfig(): Promise<PromptAuditConfig> {
  const { data } = await apiClient.get<PromptAuditConfig>(`${basePath}/config`)
  return data
}

export async function updateConfig(payload: PromptAuditUpdateRequest): Promise<PromptAuditConfig> {
  const { data } = await apiClient.put<PromptAuditConfig>(`${basePath}/config`, payload)
  return data
}

export async function getPassRetention(): Promise<PromptPassRetentionConfig> {
  const { data } = await apiClient.get<PromptPassRetentionConfig>(`${basePath}/pass-retention`)
  return normalizePassRetention(data)
}

export async function updatePassRetention(payload: PromptPassRetentionUpdateRequest): Promise<PromptPassRetentionConfig> {
  const { data } = await apiClient.put<PromptPassRetentionConfig>(`${basePath}/pass-retention`, payload)
  return normalizePassRetention(data)
}

export async function probeEndpoint(endpoint: PromptAuditEndpointDraft): Promise<PromptProbeResult> {
  const { data } = await apiClient.post<PromptProbeResult>(`${basePath}/endpoints/probe`, {
    endpoint: {
      id: endpoint.id,
      name: endpoint.name,
      protocol: 'openai_compatible',
      base_url: endpoint.base_url,
      model: endpoint.model,
      token: endpoint.token || undefined,
      timeout_ms: endpoint.timeout_ms,
      input_limit: endpoint.input_limit,
      enabled: endpoint.enabled,
    },
  })
  return data
}

export async function getRuntime(): Promise<PromptAuditRuntime> {
  const { data } = await apiClient.get<PromptAuditRuntime>(`${basePath}/runtime`)
  return data
}

export async function listEvents(
  filters: PromptEventFilters,
  page: number,
  pageSize: number,
): Promise<PromptEventPage> {
  const { data } = await apiClient.get<PromptEventPage>(`${basePath}/events`, {
    params: { page, page_size: pageSize, ...eventQueryParams(filters) },
  })
  return data
}

export async function getEvent(id: number): Promise<PromptAuditEvent> {
  const { data } = await apiClient.get<PromptAuditEvent>(`${basePath}/events/${id}`)
  return data
}

export async function analyzeEvent(id: number): Promise<PromptUserAnalysis> {
  const { data } = await apiClient.post<PromptUserAnalysis>(`${basePath}/events/${id}/analyze`, undefined, { timeout: 120_000 })
  return data
}

export async function downloadEventContext(id: number): Promise<Blob> {
  const { data } = await apiClient.get<Blob>(`${basePath}/events/${id}/context`, { responseType: 'blob' })
  return data
}

export async function deleteEvent(id: number): Promise<PromptDeleteResult> {
  const { data } = await apiClient.delete<PromptDeleteResult>(`${basePath}/events/${id}`)
  return data
}

export async function batchDeleteEvents(ids: number[]): Promise<PromptDeleteResult> {
  const { data } = await apiClient.post<PromptDeleteResult>(`${basePath}/events/batch-delete`, { ids })
  return data
}

export async function previewDelete(filters: PromptEventFilters): Promise<PromptDeletePreview> {
  const { data } = await apiClient.post<PromptDeletePreview>(
    `${basePath}/events/delete-preview`,
    eventFilterPayload(filters),
  )
  return data
}

export async function deleteEventsByFilter(
  filters: PromptEventFilters,
  preview: PromptDeletePreview,
): Promise<PromptDeleteResult> {
  const { data } = await apiClient.post<PromptDeleteResult>(`${basePath}/events/delete-by-filter`, {
    filter: eventFilterPayload(filters),
    snapshot_max_id: preview.snapshot_max_id,
    filter_hash: preview.filter_hash,
    confirmation_token: preview.confirmation_token,
    confirm: true,
  })
  return data
}

export async function listGroups(): Promise<PromptAuditGroup[]> {
  const { data } = await apiClient.get<PromptAuditGroup[]>('/admin/groups/all', {
    params: { include_inactive: true },
  })
  return data
}

export const promptAuditAPI = {
  getConfig,
  updateConfig,
  getPassRetention,
  updatePassRetention,
  probeEndpoint,
  getRuntime,
  listEvents,
  getEvent,
  analyzeEvent,
  downloadEventContext,
  deleteEvent,
  batchDeleteEvents,
  previewDelete,
  deleteEventsByFilter,
  listGroups,
}

export default promptAuditAPI
