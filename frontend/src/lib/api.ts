import { getAuthToken } from '../context/AuthContext'

const API_BASE_URL = 'http://127.0.0.1:8000'

export async function apiFetch(
  path: string,
  options: RequestInit = {},
) {
  const token = getAuthToken()

  const headers = new Headers(options.headers)

  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json')
  }

  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  return fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  })
}

export { API_BASE_URL }