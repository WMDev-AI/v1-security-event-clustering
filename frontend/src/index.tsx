import { createRoot } from 'react-dom/client'
import App from './App'
import './globals.css'

const el = document.getElementById('root')
if (!el) {
  throw new Error('Root element #root not found')
}

createRoot(el).render(<App />)
