import { Injectable } from '@angular/core';
import { DynamicDialogRef } from 'primeng/dynamicdialog';
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
  public notifyChanges(data: any, modalRef?: DynamicDialogRef) {
    if (data) {
      if (modalRef) {
        modalRef.close();
      }
      this.notify.next(data);
    }
  }
}
