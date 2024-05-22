import { Component, OnInit, ViewChild, inject } from '@angular/core';
import { Table } from 'primeng/table';
import { ITransacao } from '../../../interfaces/ITransacao';
import { ParamsTransacao } from '../../../interfaces/ParamsTransacao';
import { TransacaoUtilService } from '../../../utils/transacao-util.service';
import { NotificationService } from '../../services/notification.service';

@Component({
  selector: 'fin-base-transacao',
  templateUrl: './base-transacao.component.html'
})
export class BaseTransacaoComponent implements OnInit {
  @ViewChild('dt') dt: Table | undefined;

  protected _notificationService = inject(NotificationService);
  protected _transacaoUtilService = inject(TransacaoUtilService);
  
  protected transacoes: ITransacao[] = [];
  protected rowSelected!: ITransacao[] | null;
  protected queryParams: ParamsTransacao = {
    filterDate: new Date()
  };

  ngOnInit(): void {
    this.fetchTransacoes(this.queryParams);

    this._notificationService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.fetchTransacoes(this.queryParams);
      }
      if (res.closeModal) {
        this.rowSelected = null;
      }
    });

    this._notificationService.notifyObservable$.subscribe((res) => {
      const { date } = res;

      if (date) {
        this.queryParams.filterDate = date;
        this.fetchTransacoes(this.queryParams);
      }
    });
  }

  clear(table: Table) {
    table.clear();
  }

  applyFilterGlobal($event: any, stringVal: any) {
    this.dt!.filterGlobal(($event.target as HTMLInputElement).value, stringVal);
  }

  protected deletarTransacoes() {
    if (this.rowSelected) {
      const transacoesIds = this.rowSelected.map((item) => item.trs_id);
      this._transacaoUtilService.deletarTransacoesUtil(transacoesIds);
    }
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
      next: (transacoes: ITransacao[]) => {
        this.transacoes = transacoes;
        this.afterFetchTransacoes(transacoes);
      },
      error: (err) => console.log(err),
    });
  }

  protected afterFetchTransacoes(transacoes: ITransacao[]): void {}
}
