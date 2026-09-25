import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import App from './App';
import './i18n'; // must load before App renders
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
