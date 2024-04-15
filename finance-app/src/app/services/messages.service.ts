import { Injectable } from '@angular/core';
import { MessageService } from 'primeng/api';

@Injectable({
  providedIn: 'root'
})
export class MessagesService {
  constructor(private _messageService: MessageService) {}

  showSuccess(message: string) {
    this._messageService.add({
      severity: 'success',
      summary: 'Sucesso',
      detail: message,
    });
  }

  showError(message: string) {
    this._messageService.add({
      severity: 'error',
      summary: 'Erro',
      detail: message,
    });
  }
}
