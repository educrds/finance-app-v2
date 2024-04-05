import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, retry } from 'rxjs';
import { environment } from '../../environments/environment';
import { ITransacao } from '../interfaces/ITransacao';
import { IDropdown } from '../interfaces/IDropdown';
import { ParamsTransacao } from '../interfaces/ParamsTransacao';

@Injectable({
  providedIn: 'root',
})
export class TransacoesService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  public notify = new BehaviorSubject<any>('');
  notifyObservable$ = this.notify.asObservable();

  public notifyChanges(data: any) {
    if (data) this.notify.next(data);
  }

  getMetodosDropdown(): Observable<IDropdown[]> {
    return this._http
      .post<IDropdown[]>(`${this._api_url}transacoes/listar/metodos`, {})
      .pipe(retry(1));
  }

  getTransacoes(params: ParamsTransacao): Observable<ITransacao[]> {
    return this._http
      .post<ITransacao[]>(`${this._api_url}transacoes/listar`, { data: params })
      .pipe(retry(1));
  }

  addTransacao(dadosTransacao: ITransacao) {
    return this._http.post<ITransacao[]>(
      `${this._api_url}transacao/adicionar`,
      {
        data: dadosTransacao,
      }
    );
  }

  deletarTransacao(idTransacao: number) {
    return this._http.post(`${this._api_url}transacao/deletar`, {
      data: idTransacao,
    });
  }

  atualizarTransacao(dadosTransacao: ITransacao) {
    return this._http.post(`${this._api_url}transacao/atualizar`, {
      data: dadosTransacao,
    });
  }
}
