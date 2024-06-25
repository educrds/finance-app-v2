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

  /**
   * Obtém uma lista de categorias formatadas para um dropdown baseado no ID do tipo de categoria.
   * @param cat_tip_id - O ID do tipo de categoria para filtrar as categorias.
   * @returns Um Observable contendo uma lista de objetos IDropdown.
   */
  getCategoriasDropdown$(cat_tip_id: number): Observable<IDropdown[]> {
    return this.#_http
      .post<IDropdown[]>(`${this.#_api_url}categoria/listar-select-categorias`, {
        data: { cat_tip_id },
      })
      .pipe(shareReplay(1));
  }

  /**
   * Obtém uma lista de categorias associadas ao usuário atual.
   * @returns Um Observable contendo uma lista de objetos Categorias.
   */
  getCategoriasByUser$(): Observable<Categorias[]> {
    return this.#_http
      .post<Categorias[]>(`${this.#_api_url}categoria/listar-categorias`, {})
      .pipe(shareReplay(1));
  }

  /**
   * Adiciona uma nova categoria.
   * @param form - Um objeto do tipo Categoria contendo os dados da categoria a ser adicionada.
   * @returns Um Observable contendo o objeto Categoria adicionado.
   */
  addCategoria$(form: Categoria): Observable<Categoria> {
    return this.#_http.post<Categoria>(`${this.#_api_url}categoria/adicionar-categoria`, { data: form })
  }

  /**
   * Atualiza uma categoria existente.
   * @param form - Um objeto do tipo Categoria contendo os dados da categoria a ser atualizada.
   * @returns Um Observable contendo o objeto Categoria atualizado.
   */
  atualizarCategoria$(form: Categoria): Observable<Categoria> {
    return this.#_http.post<Categoria>(`${this.#_api_url}categoria/atualizar-categoria`, { data: form })
  }

  /**
   * Deleta uma categoria.
   * @param form - Um objeto do tipo Categoria contendo os dados da categoria a ser deletada.
   * @returns Um Observable contendo o objeto Categoria deletado.
   */
  deletarCategoria$(form: Categoria): Observable<Categoria> {
    return this.#_http.post<Categoria>(`${this.#_api_url}categoria/deletar-categoria`, { data: form })
  }
}
