import client from './client'
export const getThreats = (params?: Record<string, unknown>) => client.get('/api/threats', { params }).then(r => r.data)
export const getThreat = (id: string) => client.get(`/api/threats/${id}`).then(r => r.data)
export const getRules = (params?: Record<string, unknown>) => client.get('/api/threats/rules', { params }).then(r => r.data)
export const getClouds = () => client.get('/api/threats/clouds').then(r => r.data)
