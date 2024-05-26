import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, retry } from 'rxjs';
import { environment } from '../../environments/environment';
import { IDropdown } from '../interfaces/Dropdown';
import { Categoria, Categorias } from '../interfaces/Categorias';
import { ICategoriasService } from '../interfaces/ICategoriasService';

@Injectable({
  providedIn: 'root',
})
export class CategoriasService implements ICategoriasService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  getCategoriasDropdown(cat_tip_id: number): Observable<IDropdown[]> {
    return this._http
      .post<IDropdown[]>(`${this._api_url}categorias/listar-select`, {
        data: { cat_tip_id: cat_tip_id },
      })
      .pipe(retry(1));
  }

  getCategorias(): Observable<Categorias[]> {
    return this._http
      .post<Categorias[]>(`${this._api_url}categorias/listar`, {})
      .pipe(retry(1));
  }

  addCategoria(form: Categoria): Observable<Categoria> {
    return this._http
      .post<Categoria>(`${this._api_url}categoria/adicionar`, { data: form })
      .pipe(retry(1));
  }

  atualizarCategoria(form: Categoria): Observable<Categoria> {
    return this._http
      .post<Categoria>(`${this._api_url}categoria/atualizar`, { data: form })
      .pipe(retry(1));
  }

  deletarCategoria(form: Categoria): Observable<Categoria> {
    return this._http
      .post<Categoria>(`${this._api_url}categoria/deletar`, { data: form })
      .pipe(retry(1));
  }
}
