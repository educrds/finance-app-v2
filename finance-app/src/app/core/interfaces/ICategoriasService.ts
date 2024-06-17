import { Observable } from "rxjs";
import { IDropdown } from "./Dropdown";
import { Categoria, Categorias } from "./Categorias";

export interface ICategoriasService {
  getCategoriasDropdown$(cat_tip_id: number): Observable<IDropdown[]>;
  getCategoriasByUser$(): Observable<Categorias[]>;
  addCategoria$(form: Categoria): Observable<Categoria>;
  atualizarCategoria$(form: Categoria): Observable<Categoria>;
  deletarCategoria$(form: Categoria): Observable<Categoria>;
}
