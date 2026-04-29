import client from './client'
export const getAssets = (params?: Record<string, unknown>) => client.get('/api/assets', { params }).then(r => r.data)
export const getAssetSignals = (id: string) => client.get(`/api/assets/${id}/signals`).then(r => r.data)
export const triageAsset = (id: string, patch: Record<string, unknown>) => client.patch(`/api/assets/${id}/triage`, patch).then(r => r.data)
export const deleteAsset = (id: string) => client.delete(`/api/assets/${id}`)
