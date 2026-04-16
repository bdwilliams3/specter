import client from './client'
export const getVulns = (params?: Record<string, unknown>) => client.get('/api/vulnerabilities', { params }).then(r => r.data)
export const getVuln = (id: string) => client.get(`/api/vulnerabilities/${id}`).then(r => r.data)
