import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, retry } from 'rxjs';
import { environment } from '../../environments/environment';
import { ITransacao } from '../interfaces/ITransacao';
import { ITransacoesSoma } from '../interfaces/ITransacoesSoma';

@Injectable({
  providedIn: 'root',
})
export class TransacoesService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  public notify = new BehaviorSubject<any>('');
  notifyObservable$ = this.notify.asObservable();

  public notifyChanges(data: any) {
    if(data){
      this.notify.next(data)
    }
  }

  getTransacoes(params: Date): Observable<ITransacao[]> {
    return this._http
      .post<ITransacao[]>(`${this._api_url}transacoes/listar`, { data: params })
      .pipe(retry(1));
  }

  getTransacoesSomatorio(params: Date): Observable<ITransacoesSoma[]> {
    return this._http
      .post<ITransacoesSoma[]>(`${this._api_url}transacoes/somatorio`, { data: params })
      .pipe(retry(1));
  }

  getReceitas(params: Date): Observable<ITransacao[]> {
    return this._http
      .post<ITransacao[]>(`${this._api_url}transacoes/listar/receitas`, { data: params })
      .pipe(retry(1));
  }

  getDespesas(params: Date): Observable<ITransacao[]> {
    return this._http
      .post<ITransacao[]>(`${this._api_url}transacoes/listar/despesas`, { data: params })
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

  deletarTransacao(idTransacao: string) {
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