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
      .post<ITransacao[]>(`${this._api_url}transacoes/listar`, {})
      .pipe(retry(1));
  }

  getReceitas(): Observable<ITransacao[]> {
    return this._http
      .post<ITransacao[]>(`${this._api_url}transacoes/listar/receitas`, {})
      .pipe(retry(1));
  }

  getDespesas(): Observable<ITransacao[]> {
    return this._http
      .post<ITransacao[]>(`${this._api_url}transacoes/listar/despesas`, {})
      .pipe(retry(1));
  }


  addTransacao(dadosTransacao: ITransacao) {
    return this._http
      .post<ITransacao[]>(`${this._api_url}transacao/adicionar`, {
        data: dadosTransacao,
      });
  }
}
