import { IDropdown } from './IDropdown';

interface CategoriaCor {
  cat_color: string;
}

export type Categoria = IDropdown & CategoriaCor;
