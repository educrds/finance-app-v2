import { IDropdown } from './IDropdown';

interface Categoria {
  cat_color: string;
}

export type Categorias = IDropdown & Categoria;
