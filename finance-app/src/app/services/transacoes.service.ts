import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, retry } from 'rxjs';
import { environment } from '../../environments/environment';
import { ITransacao } from '../interfaces/ITransacao';

@Injectable({
  providedIn: 'root',
})
export class TransacoesService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  getTransacoes(): Observable<ITransacao[]> {
    return this._http
      .post<ITransacao[]>(`${this._api_url}transacoes/listar`, {
        teste: 'teste',
      })
      .pipe(retry(1));
  }
}
