// i18n setup — English (default) + Bahasa Indonesia (PRD §43).
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import en from './locales/en.json';
import id from './locales/id.json';

const STORAGE_KEY = 'jawaker_lang';

const saved = localStorage.getItem(STORAGE_KEY);
const detected = navigator.language.startsWith('id') ? 'id' : 'en';
const lng = saved ?? detected;

i18n
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      id: { translation: id },
    },
    lng,
    fallbackLng: 'en',
    interpolation: { escapeValue: false },
  });

// Persist language changes.
i18n.on('languageChanged', (lang) => {
  localStorage.setItem(STORAGE_KEY, lang);
});

export default i18n;
