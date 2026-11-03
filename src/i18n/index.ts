import { es } from "./es";
import { en } from "./en";

export type Language = "es" | "en";
export const translations = { es, en };

export function getTranslation(lang: Language = "es") {
  return translations[lang] || translations.es;
}
