import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class NotificationService {
  // Subject que mantém o estado atual da notificação
  public notify = new Subject<any>();

  // Observable público que permite que outras partes da aplicação se inscrevam para receber notificações
  notifyObservable$ = this.notify.asObservable();

  // Método para emitir novas notificações
  public notifyChanges(data: any) {
    if (data) this.notify.next(data);
  }
}