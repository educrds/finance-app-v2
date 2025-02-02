import { Observable } from "rxjs";
import { IDropdown } from "../models/Dropdown";
import { Categoria, Categorias } from "../models/Categorias";

export interface ICategoriasService {
  getCategoriasDropdown$(cat_tip_id: number): Observable<IDropdown[]>;
  getCategoriasByUser$(): Observable<Categorias[]>;
  addCategoria$(form: Categoria): Observable<{ message: string }>;
  atualizarCategoria$(form: Categorias): Observable<{ message: string }>;
  deletarCategoria$(form: Categorias): Observable<{ message: string }>;
}
