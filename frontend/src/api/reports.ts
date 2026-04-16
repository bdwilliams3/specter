import client from './client'
export const exportReport = (format: string, entity: string) =>
  client.get('/api/reports/export', { params: { format, entity }, responseType: 'blob' }).then(r => r.data)
