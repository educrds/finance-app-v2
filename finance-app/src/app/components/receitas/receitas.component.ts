import { Component, OnInit } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { TransacoesService } from '../../services/transacoes.service';
import { DateFilterService } from '../../services/date-filter.service';
import { TransacaoUtilService } from '../../utils/transacao-util.service';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';

@Component({
  selector: 'fin-receitas',
  templateUrl: './receitas.component.html',
  styleUrl: './receitas.component.scss',
})
export class ReceitasComponent implements OnInit {
  protected transacoes: ITransacao[] = [];
  protected rowSelected!: ITransacao | null;

  private queryParams: ParamsTransacao = {
    filterDate: new Date(),
    idTipoTransacao: 1
  };

  constructor(
    private _transacoesService: TransacoesService,
    private _dateFilterService: DateFilterService,
    private _transacaoUtilService: TransacaoUtilService
  ) {}

  ngOnInit(): void {
    this.fetchTransacoes(this.queryParams);

    this._transacoesService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.fetchTransacoes(this.queryParams);
      }
      if (res.closeModal) {
        this.rowSelected = null;
      }
    });

    this._dateFilterService.notifyObservable$.subscribe((res) => {
      const { date } = res;

      if (date) {
        this.queryParams.filterDate = date;
        this.fetchTransacoes(this.queryParams);
      }
    });
  }

  protected editarTransacao(transacao: ITransacao) {
    this._transacaoUtilService.editarTransacaoUtil(transacao);
  }

  protected deletarTransacao(idTransacao: number, isParcelado: boolean) {
    this._transacaoUtilService.deletarTransacaoUtil(idTransacao, isParcelado);
  }

  protected checkStatus(transacao: ITransacao): string {
    return this._transacaoUtilService.checkStatusUtil(transacao);
  }

  private fetchTransacoes(params: ParamsTransacao) {
    this._transacaoUtilService.getTransacoesUtil(params).subscribe({
      next: (transacoes: ITransacao[]) => (this.transacoes = transacoes),
      error: (err) => console.log(err),
    });
  }
}
