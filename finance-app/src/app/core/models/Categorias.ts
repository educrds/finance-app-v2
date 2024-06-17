import { IDropdown } from "./Dropdown";

type CategoriaCor = {
  cat_color: string;
}
export type Categorias = {
  cat_id: number;
  cat_nome: string;
  cat_cor: string;
  usr_id: number | null;
  cat_tip_nome: string;
}

export type Categoria = IDropdown & CategoriaCor;
