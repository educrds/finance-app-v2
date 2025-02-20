import { HttpClient } from "@angular/common/http";
import { Injectable, inject } from "@angular/core";
import { Observable, shareReplay, take } from "rxjs";
import { environment } from "../../../environments/environment";
import { Transacao } from "../models/Transacao";
import { IDropdown } from "../models/Dropdown";
import { ParamsTransacao } from "../models/ParamsTransacao";
import { ITransacoesService } from "../interfaces/ITransacoesService";
import { BarChart } from "../models/Chart";

@Injectable({
  providedIn: "root",
})
export class TransacoesService implements ITransacoesService {
  readonly #_api_url = environment.api_url;
  readonly #_http = inject(HttpClient);

  /**
   * Obtém uma lista de métodos de transação formatados para um dropdown.
   * @returns Um Observable contendo uma lista de objetos IDropdown.
   */
  public getMetodosDropdown$(): Observable<IDropdown[]> {
    return this.#_http
      .post<IDropdown[]>(`${this.#_api_url}transacao/listar-metodos`, {})
      .pipe(take(1), shareReplay(1));
  }

  /**
   * Obtém uma lista de transações com base nos parâmetros fornecidos.
   * @param params - Os parâmetros de filtro para listar as transações.
   * @returns Um Observable contendo uma lista de objetos Transacao.
   */
  public getTransacoes$(params: ParamsTransacao): Observable<Transacao[]> {
    return this.#_http
      .post<Transacao[]>(`${this.#_api_url}transacao/listar-transacoes`, { data: params })
      .pipe(take(1), shareReplay(1));
  }

  /**
   * Obtém dados de gráfico comparativo com base nos parâmetros fornecidos.
   * @param params - Os parâmetros de filtro para obter o gráfico comparativo.
   * @returns Um Observable contendo um objeto BarChartResult.
   */
  public getComparativoChart$(params: ParamsTransacao): Observable<BarChart[]> {
    return this.#_http
      .post<BarChart[]>(`${this.#_api_url}chart/chart-anual`, {
        data: params,
      })
      .pipe(take(1), shareReplay(1));
  }

  /**
   * Adiciona uma nova transação.
   * @param dadosTransacao - Um objeto do tipo Transacao contendo os dados da transação a ser adicionada.
   * @returns Um Observable contendo a lista de objetos Transacao atualizada.
   */
  public addTransacao$(dadosTransacao: Transacao): Observable<Transacao[]> {
    return this.#_http.post<Transacao[]>(`${this.#_api_url}transacao/adicionar-transacao`, {
      data: dadosTransacao,
    });
  }

  /**
   * Deleta uma transação com base no ID fornecido.
   * @param id_transacao - O ID da transação a ser deletada.
   * @param trs_parcelado - Opcional. Indica se a transação é parcelada.
   * @returns Um Observable indicando o resultado da operação.
   */
  public deletarTransacao$(id_transacao: number | undefined, trs_parcelado?: boolean): Observable<any> {
    return this.#_http.post(`${this.#_api_url}transacao/deletar-transacao`, {
      data: {
        id_transacao: id_transacao,
        trs_parcelado: trs_parcelado,
      },
    });
  }

  /**
   * Deleta todas as transações com base no ID fornecido.
   * @param id_transacao - O ID da transação para deletar todas as ocorrências.
   * @returns Um Observable indicando o resultado da operação.
   */
  public deletarTodasTransacoesById$(id_transacao: number): Observable<any> {
    return this.#_http.post(`${this.#_api_url}transacao/deletar-todas`, {
      data: id_transacao,
    });
  }

  /**
   * Atualiza uma transação existente.
   * @param dadosTransacao - Um objeto do tipo Transacao contendo os dados da transação a ser atualizada.
   * @returns Um Observable indicando o resultado da operação.
   */
  public atualizarTransacao$(dadosTransacao: Transacao): Observable<any> {
    return this.#_http.post(`${this.#_api_url}transacao/atualizar-transacao`, { data: dadosTransacao });
  }
}
