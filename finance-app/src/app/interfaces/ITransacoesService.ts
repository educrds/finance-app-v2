import { Observable } from "rxjs";
import { ParamsTransacao } from "./ParamsTransacao";
import { Transacao } from "./Transacao";
import { IDropdown } from "./Dropdown";

export interface ITransacoesService {
  getMetodosDropdown(): Observable<IDropdown[]>;
  getTransacoes(params: ParamsTransacao): Observable<Transacao[]>;
  addTransacao(dadosTransacao: Transacao): Observable<Transacao[]>;
  deletarTransacao(id_transacao: number, trs_parcelado?: boolean): Observable<any>;
  atualizarTransacao(dadosTransacao: Transacao): Observable<any>;
  deletarTodasTransacoesById(id_transacao: number): Observable<any>;
  }
