import client from './client'
export const getThreats = (params?: Record<string, unknown>) => client.get('/api/threats', { params }).then(r => r.data)
export const getThreat = (id: string) => client.get(`/api/threats/${id}`).then(r => r.data)
