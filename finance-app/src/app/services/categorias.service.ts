import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, retry } from 'rxjs';
import { environment } from '../../environments/environment';
import { IDropdown } from '../interfaces/IDropdown';
import { Categoria } from '../interfaces/Categorias';

@Injectable({
  providedIn: 'root',
})
export class CategoriasService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  getCategorias(): Observable<Categoria[]> {
    return this._http
      .post<Categoria[]>(`${this._api_url}categorias/listar`, {})
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
