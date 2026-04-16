import client from './client'
export const testIntegration = (name: string) => client.post(`/api/integrations/${name}/test`).then(r => r.data)
