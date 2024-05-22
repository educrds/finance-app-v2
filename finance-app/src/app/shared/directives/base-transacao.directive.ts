import { Directive, ViewChild, WritableSignal, inject, signal } from '@angular/core';
import { Table } from 'primeng/table';
import { Transacao } from '../../interfaces/Transacao';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';
import { TransacaoUtilService } from '../services/transacao-util.service';
import { NotificationService } from '../services/notification.service';

@Directive({
  selector: '[finBaseTransacao]'
})
export class BaseTransacaoDirective {
  @ViewChild('dt') dt: Table | undefined;

  protected _notificationService = inject(NotificationService);
  protected _transacaoUtilService = inject(TransacaoUtilService);
  
  protected transacoes: WritableSignal<Transacao[]> = signal([]);
  protected rowSelected: WritableSignal<Transacao[]> = signal([]);
  protected queryParams: WritableSignal<ParamsTransacao> = signal({
    filterDate: new Date()
  });

  ngOnInit(): void {
    this.fetchTransacoes(this.queryParams());

    this._notificationService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.fetchTransacoes(this.queryParams());
      }
      if (res.closeModal) {
        this.rowSelected.set([]);
      }
    });

    this._notificationService.notifyObservable$.subscribe((res) => {
      const { date } = res;

      if (date) {
        this.queryParams().filterDate = date;
        this.fetchTransacoes(this.queryParams());
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
    if (this.rowSelected()) {
      const transacoesIds = this.rowSelected().map((item) => item.trs_id);
      this._transacaoUtilService.deletarTransacoesUtil(transacoesIds);
    }
  }

  protected editarTransacao(transacao: Transacao) {
    this._transacaoUtilService.editarTransacaoUtil(transacao);
  }

  protected deletarTransacao(idTransacao: number, isParcelado: boolean) {
    this._transacaoUtilService.deletarTransacaoUtil(idTransacao, isParcelado);
  }

  protected checkStatus(transacao: Transacao): string {
    return this._transacaoUtilService.checkStatusUtil(transacao);
  }

  private fetchTransacoes(params: ParamsTransacao) {
    this._transacaoUtilService.getTransacoesUtil(params).subscribe({
      next: (transacoes: Transacao[]) => {
        this.transacoes.set(transacoes);
        this.afterFetchTransacoes(transacoes);
      },
      error: (err) => console.log(err),
    });
  }

  protected afterFetchTransacoes(transacoes: Transacao[]): void {}

}
