import client from './client'
export const getThreats = (params?: Record<string, unknown>) => client.get('/api/threats', { params }).then(r => r.data)
export const getThreat = (id: string) => client.get(`/api/threats/${id}`).then(r => r.data)
export const getRules = (params?: Record<string, unknown>) => client.get('/api/threats/rules', { params }).then(r => r.data)
export const getClouds = () => client.get('/api/threats/clouds').then(r => r.data)
export const updateRule = (ruleId: string, patch: Record<string, unknown>) => client.patch(`/api/rules/${ruleId}`, patch).then(r => r.data)
export const bulkUpdateRules = (updates: Array<{ rule_id: string; patch: Record<string, unknown> }>) => client.patch('/api/rules', updates).then(r => r.data)
