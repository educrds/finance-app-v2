import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import {
  Observable,
  retry,
  shareReplay,
  take
} from 'rxjs';
import { environment } from '../../../environments/environment';
import { Transacao } from '../models/Transacao';
import { IDropdown } from '../models/Dropdown';
import { ParamsTransacao } from '../models/ParamsTransacao';
import { ITransacoesService } from '../interfaces/ITransacoesService';
import { BarChartResult } from '../models/Chart';

@Injectable({
  providedIn: 'root',
})
export class TransacoesService implements ITransacoesService {
  #_api_url = environment.api_url;
  #_http = inject(HttpClient)

  public getMetodosDropdown$(): Observable<IDropdown[]> {
    return this.#_http
      .post<IDropdown[]>(`${this.#_api_url}transacoes/listar/metodos`, {})
      .pipe(take(1), retry(1), shareReplay(1));
  }

  public getTransacoes$(params: ParamsTransacao): Observable<Transacao[]> {
    return this.#_http
      .post<Transacao[]>(`${this.#_api_url}transacoes/listar`, { data: params })
      .pipe(take(1), retry(1), shareReplay(1));
  }

  public getComparativoChart$(params: ParamsTransacao): Observable<BarChartResult> {
    return this.#_http
      .post<BarChartResult>(`${this.#_api_url}charts/comparativo-anual`, {
        data: params,
      })
      .pipe(take(1), retry(1), shareReplay(1));
  }

  public addTransacao$(dadosTransacao: Transacao): Observable<Transacao[]> {
    return this.#_http.post<Transacao[]>(`${this.#_api_url}transacao/adicionar`, {
      data: dadosTransacao,
    });
  }

  public deletarTransacao$(id_transacao: number, trs_parcelado?: boolean): Observable<any> {
    return this.#_http.post(`${this.#_api_url}transacao/deletar`, {
      data: {
        id_transacao: id_transacao,
        trs_parcelado: trs_parcelado,
      },
    });
  }

  public deletarTodasTransacoesById$(id_transacao: number): Observable<any> {
    return this.#_http.post(`${this.#_api_url}transacao/deletar-todas`, {
      data: id_transacao,
    });
  }

  public atualizarTransacao$(dadosTransacao: Transacao): Observable<any> {
    return this.#_http
      .post(`${this.#_api_url}transacao/atualizar`, {
        data: dadosTransacao,
      })
  }
}
