import client from './client'
export const triggerScan = (scanner: string, target: string) => client.post('/api/scans/trigger', { scanner, target }).then(r => r.data)
export const getScans = () => client.get('/api/scans').then(r => r.data)
export const getScanners = () => client.get('/api/scans/scanners').then(r => r.data)
