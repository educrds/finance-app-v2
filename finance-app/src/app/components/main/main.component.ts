import { Component, OnInit } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { take } from 'rxjs';
import { ITransacao } from '../../interfaces/ITransacao';
import { NotificationService } from '../../services/notification.service';
import { ConfirmationService } from 'primeng/api';
import { ModalTransacaoComponent } from '../../templates/modal-transacao/modal-transacao.component';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { DateFilterService } from '../../services/date-filter.service';
import { ITransacoesSoma } from '../../interfaces/ITransacoesSoma';
import { TransacaoUtilService } from '../../utils/transacao-util.service';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrl: './main.component.scss',
  providers: [ConfirmationService, DialogService],
})
export class MainComponent implements OnInit {
  protected transacoes: ITransacao[] = [];
  protected somatorio!: ITransacoesSoma;
  protected rowSelected!: ITransacao | null;

  private queryParams: Date = new Date();

  constructor(
    private _transacoesService: TransacoesService,
    private _dateFilterService: DateFilterService,
    private _transacaoUtilService: TransacaoUtilService
  ) {}

  ngOnInit(): void {
    this.fetchTransacoes();

    this._transacoesService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.fetchTransacoes();
      }
      if (res.closeModal) {
        this.rowSelected = null;
      }
    });

    this._dateFilterService.notifyObservable$.subscribe((res) => {
      const { date } = res;
      if (date) {
        this.queryParams = date;
        this.fetchTransacoes();
      }
    });
  }

  private fetchTransacoes() {
    this._transacoesService
      .getTransacoes(this.queryParams)
      .pipe(take(1))
      .subscribe({
        next: (res) => {
          this.transacoes = res;
          this.somatorio = this._transacaoUtilService.obterSomatorioTransacoes(
            this.transacoes
          );
        },
        error: (err) => console.log(err),
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
}
