import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable, retry } from 'rxjs';
import { environment } from '../../environments/environment';
import { Transacao } from '../interfaces/Transacao';
import { IDropdown } from '../interfaces/Dropdown';
import { ParamsTransacao } from '../interfaces/ParamsTransacao';
import { ITransacoesService } from '../interfaces/ITransacoesService';

@Injectable({
  providedIn: 'root',
})
export class TransacoesService implements ITransacoesService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  getMetodosDropdown(): Observable<IDropdown[]> {
    return this._http
      .post<IDropdown[]>(`${this._api_url}transacoes/listar/metodos`, {})
      .pipe(retry(1));
  }

  getTransacoes(params: ParamsTransacao): Observable<Transacao[]> {
    return this._http
      .post<Transacao[]>(`${this._api_url}transacoes/listar`, { data: params })
      .pipe(retry(1));
  }

  addTransacao(dadosTransacao: Transacao): Observable<Transacao[]> {
    return this._http.post<Transacao[]>(`${this._api_url}transacao/adicionar`, {
      data: dadosTransacao,
    });
  }

  deletarTransacao(idTransacao: number): Observable<any> {
    return this._http.post(`${this._api_url}transacao/deletar`, {
      data: idTransacao,
    });
  }

  atualizarTransacao(dadosTransacao: Transacao): Observable<any> {
    return this._http.post(`${this._api_url}transacao/atualizar`, {
      data: dadosTransacao,
    });
  }
}
