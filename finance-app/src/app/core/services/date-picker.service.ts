import { Injectable } from '@angular/core';
import { BehaviorSubject, distinctUntilChanged, shareReplay } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class DatePickerService {
  // BehaviorSubject que mantém o estado atual da data
  public datePicker = new BehaviorSubject<Date>(this.getCurrentMonthFormatted());
  
  // Observable público que permite que outras partes da aplicação se inscrevam para obter data.
  // Operador distinctUntilChanged para evitar subscriptions valores duplicados
  datePickerObservable$ = this.datePicker.asObservable()
    .pipe(distinctUntilChanged((prev, curr) => prev.getTime() === curr.getTime()), shareReplay(1));
  
  // Método para emitir novas notificações
  public notifyDateChanges(date: Date) {
    if (date) this.datePicker.next(date);
  }
  
  private getCurrentMonthFormatted() {
    const date = new Date();
    return new Date(date.getFullYear(), date.getMonth(), 1);
  }
}