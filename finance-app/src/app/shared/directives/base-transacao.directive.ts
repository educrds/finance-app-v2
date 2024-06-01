import { Directive, OnDestroy, OnInit, WritableSignal, inject, signal } from '@angular/core';
import { Transacao } from '../../interfaces/Transacao';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';
import { TransacaoUtilService } from '../services/transacao-util.service';
import { NotificationService } from '../services/notification.service';
import { Subscription } from 'rxjs';
import { DatePickerService } from '../../services/date-picker.service';
import { TransacoesService } from '../../services/transacoes.service';

@Directive({
  selector: '[finBaseTransacao]'
})
export class BaseTransacaoDirective implements OnInit, OnDestroy {
  protected _notificationService = inject(NotificationService);
  protected _transacaoUtilService = inject(TransacaoUtilService);
  protected _transacoesService = inject(TransacoesService);
  protected _datePickerService = inject(DatePickerService);
  
  protected transacoes: WritableSignal<Transacao[]> = signal([]);
  protected rowSelected: WritableSignal<Transacao[]> = signal([]);
  protected queryParams: WritableSignal<ParamsTransacao> = signal({});

  private _subscription!: Subscription;

  ngOnInit(): void {
    this._subscription = this._datePickerService.datePickerObservable$.subscribe((date) => {
      if (date) {
        this.queryParams().filterDate = date;
        this.fetchTransacoes(this.queryParams());
      }
    })

    this._subscription = this._notificationService.notifyObservable$.subscribe((res) => {
      const { refresh, closeModal } = res;

      if (refresh) {
        this.fetchTransacoes(this.queryParams());
      }

      if (closeModal) {
        this.rowSelected.set([]);
      }
    });
    
  }

  private fetchTransacoes(params: ParamsTransacao) {
    this._subscription = this._transacoesService.getTransacoes(params).subscribe({
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
