import { Observable } from "rxjs";
import { ParamsTransacao } from "./ParamsTransacao";
import { Transacao } from "./Transacao";
import { IDropdown } from "./Dropdown";

export interface ITransacoesService {
  getMetodosDropdown(): Observable<IDropdown[]>;
  getTransacoes(params: ParamsTransacao): Observable<Transacao[]>;
  addTransacao(dadosTransacao: Transacao): Observable<Transacao[]>;
  deletarTransacao(idTransacao: number): Observable<any>;
  atualizarTransacao(dadosTransacao: Transacao): Observable<any>;
}
