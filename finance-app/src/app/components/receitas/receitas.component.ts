import { Component, OnInit } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { TransacoesService } from '../../services/transacoes.service';
import { take } from 'rxjs';
import { DateFilterService } from '../../services/date-filter.service';
import { TransacaoUtilService } from '../../utils/transacao-util.service';

@Component({
  selector: 'fin-receitas',
  templateUrl: './receitas.component.html',
  styleUrl: './receitas.component.scss',
})
export class ReceitasComponent implements OnInit {
  protected transacoes: ITransacao[] = [];
  protected rowSelected!: ITransacao | null;

  private queryParams: Date = new Date();

  constructor(
    private _transacoesService: TransacoesService,
    private _dateFilterService: DateFilterService,
    private _transacaoUtilService: TransacaoUtilService
  ) {}

  ngOnInit(): void {
    this.getReceitas();

    this._transacoesService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.getReceitas();
      }
      if (res.closeModal) {
        this.rowSelected = null;
      }
    });

    this._dateFilterService.notifyObservable$.subscribe((res) => {
      const { date } = res;

      if (date) {
        this.queryParams = date;
        this.getReceitas();
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

  private getReceitas() {
    this._transacoesService
      .getReceitas(this.queryParams)
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.transacoes = res),
        error: (err) => console.log(err),
      });
  }
}
