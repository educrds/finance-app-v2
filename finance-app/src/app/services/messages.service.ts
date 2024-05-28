import { Injectable, inject } from '@angular/core';
import { ConfirmationService, MessageService } from 'primeng/api';

@Injectable({
  providedIn: 'root',
})
export class MessagesService {
  private _confirmationService = inject(ConfirmationService);
  private _messageService = inject(MessageService);

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

  public confirm(
    message: string,
    header: string,
    accept: () => void,
    reject?: () => void
  ) {
    this._confirmationService.confirm({
      message: message,
      header: header,
      icon: 'pi pi-exclamation-triangle',
      acceptIcon: 'none',
      rejectIcon: 'none',
      rejectButtonStyleClass: 'p-button-text',
      accept: accept,
      reject: reject,
    });
  }
}
