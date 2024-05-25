import { Directive, OnDestroy, OnInit, WritableSignal, inject, signal } from '@angular/core';
import { Transacao } from '../../interfaces/Transacao';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';
import { TransacaoUtilService } from '../services/transacao-util.service';
import { NotificationService } from '../services/notification.service';
import { Subscription } from 'rxjs';

@Directive({
  selector: '[finBaseTransacao]'
})
export class BaseTransacaoDirective implements OnInit, OnDestroy {
  protected _notificationService = inject(NotificationService);
  protected _transacaoUtilService = inject(TransacaoUtilService);
  
  protected transacoes: WritableSignal<Transacao[]> = signal([]);
  protected rowSelected: WritableSignal<Transacao[]> = signal([]);
  protected queryParams: WritableSignal<ParamsTransacao> = signal({
    filterDate: new Date()
  });

  private _subscription!: Subscription;

  ngOnInit(): void {
    this.fetchTransacoes(this.queryParams());

    this._subscription = this._notificationService.notifyObservable$.subscribe((res) => {
      const { refresh, closeModal, date } = res;

      if (refresh) {
        this.fetchTransacoes(this.queryParams());
      }

      if (closeModal) {
        this.rowSelected.set([]);
      }

      if (date) {
        this.queryParams().filterDate = date;
        this.fetchTransacoes(this.queryParams());
      }
    });
  }

  private fetchTransacoes(params: ParamsTransacao) {
    this._subscription = this._transacaoUtilService.getTransacoesUtil(params).subscribe({
      next: (transacoes: Transacao[]) => {
        this.transacoes.set(transacoes);
        this.afterFetchTransacoes(transacoes);
      },
      error: (err) => console.log(err),
    });
  }

  protected afterFetchTransacoes(transacoes: Transacao[]): void {}

  ngOnDestroy(): void {
    if(this._subscription) this._subscription.unsubscribe();
  }
}
