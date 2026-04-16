import client from './client'
export const getAssets = (params?: Record<string, unknown>) => client.get('/api/assets', { params }).then(r => r.data)
export const deleteAsset = (id: string) => client.delete(`/api/assets/${id}`)
