import client from './client'
export const getGraph = (assetId?: string) => client.get('/api/graph', { params: assetId ? { asset_id: assetId } : {} }).then(r => r.data)
