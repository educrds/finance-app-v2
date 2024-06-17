import { Observable } from "rxjs";
import { ParamsTransacao } from "../models/ParamsTransacao";
import { Transacao } from "../models/Transacao";
import { IDropdown } from "../models/Dropdown";
import { BarChartResult } from "../models/Chart";

export interface ITransacoesService {
  getMetodosDropdown$(): Observable<IDropdown[]>;
  getTransacoes$(params: ParamsTransacao): Observable<Transacao[]>;
  addTransacao$(dadosTransacao: Transacao): Observable<Transacao[]>;
  deletarTransacao$(id_transacao: number, trs_parcelado?: boolean): Observable<any>;
  atualizarTransacao$(dadosTransacao: Transacao): Observable<any>;
  deletarTodasTransacoesById$(id_transacao: number): Observable<any>;
  getComparativoChart$(params: ParamsTransacao): Observable<BarChartResult>;
  }
