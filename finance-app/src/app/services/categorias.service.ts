import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, retry } from 'rxjs';
import { environment } from '../../environments/environment';
import { IDropdown } from '../interfaces/IDropdown';

@Injectable({
  providedIn: 'root',
})
export class CategoriasService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  getCategorias(): Observable<IDropdown[]> {
    return this._http
      .post<IDropdown[]>(`${this._api_url}categorias/listar`, {})
      .pipe(retry(1));
  }
}
