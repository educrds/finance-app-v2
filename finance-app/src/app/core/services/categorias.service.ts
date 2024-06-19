import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable, retry, shareReplay } from 'rxjs';
import { environment } from '../../../environments/environment';
import { IDropdown } from '../models/Dropdown';
import { Categoria, Categorias } from '../models/Categorias';
import { ICategoriasService } from '../interfaces/ICategoriasService';

@Injectable({
  providedIn: 'root',
})
export class CategoriasService implements ICategoriasService {
  #_api_url = environment.api_url;
  #_http = inject(HttpClient)

  getCategoriasDropdown$(cat_tip_id: number): Observable<IDropdown[]> {
    return this.#_http
      .post<IDropdown[]>(`${this.#_api_url}categoria/listar-select-categorias`, {
        data: { cat_tip_id: cat_tip_id },
      })
      .pipe(retry(1), shareReplay(1));
  }

  getCategoriasByUser$(): Observable<Categorias[]> {
    return this.#_http
      .post<Categorias[]>(`${this.#_api_url}categoria/listar-categorias`, {})
      .pipe(retry(1), shareReplay(1));
  }

  addCategoria$(form: Categoria): Observable<Categoria> {
    return this.#_http
      .post<Categoria>(`${this.#_api_url}categoria/adicionar-categoria`, { data: form })
      .pipe(retry(1));
  }

  atualizarCategoria$(form: Categoria): Observable<Categoria> {
    return this.#_http
      .post<Categoria>(`${this.#_api_url}categoria/atualizar-categoria`, { data: form })
      .pipe(retry(1));
  }

  deletarCategoria$(form: Categoria): Observable<Categoria> {
    return this.#_http
      .post<Categoria>(`${this.#_api_url}categoria/deletar-categoria`, { data: form })
      .pipe(retry(1));
  }
}
