import { Component } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { ITransacao } from '../../interfaces/ITransacao';
import { take } from 'rxjs';
import { DateFilterService } from '../../services/date-filter.service';
import { TransacaoUtilService } from '../../utils/transacao-util.service';

@Component({
  selector: 'fin-despesas',
  templateUrl: './despesas.component.html',
  styleUrl: './despesas.component.scss',
})
export class DespesasComponent {
  protected transacoes: ITransacao[] = [];
  protected rowSelected!: ITransacao | null;

  private queryParams: Date = new Date();

  constructor(
    private _transacoesService: TransacoesService,
    private _dateFilterService: DateFilterService,
    private _transacaoUtilService: TransacaoUtilService
  ) {}

  ngOnInit(): void {
    this.getDespesas();

    this._transacoesService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.getDespesas();
      }
      if (res.closeModal) {
        this.rowSelected = null;
      }
    });

    this._dateFilterService.notifyObservable$.subscribe((res) => {
      const { date } = res;
      if (date) {
        this.queryParams = date;
        this.getDespesas();
      }
    });
  }

  protected editarTransacao(transacao: ITransacao) {
    this._transacaoUtilService.editarTransacaoUtil(transacao);
  }

  protected deletarTransacao(idTransacao: number) {
    this._transacaoUtilService.deletarTransacaoUtil(idTransacao);
  }

  protected checkStatus(transacao: ITransacao): string | undefined {
    return this._transacaoUtilService.checkStatusUtil(transacao);
  }

  private getDespesas() {
    this._transacoesService
      .getDespesas(this.queryParams)
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.transacoes = res),
        error: (err) => console.log(err),
      });
  }
}
