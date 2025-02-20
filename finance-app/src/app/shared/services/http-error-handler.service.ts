import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { throwError } from 'rxjs';
import { MessagesService } from '../../core/services/messages.service';
import { StorageService } from '../../core/services/storage.service';

@Injectable({
  providedIn: 'root',
})
export class HttpErrorHandlerService {
  #_router = inject(Router);
  #_messagesService= inject(MessagesService);
  #_storageService= inject(StorageService);

  handleHttpError(error: HttpErrorResponse) {
    const errorActions: { [key:number]: () => void } = {
      401: () => this._handleUnauthorized(error),
      403: () => this._handleUnauthorized(error),
      404: () => this._handleNotFound(),
      500: () => this._handleServerError()
    }

    const action = errorActions[error.status];
    if(action){
      action();
    } else {
      this._handleUnknownError(error.status);
    }

    return throwError(() => new Error("Error ao fazer requisição."));
  }

  private _handleUnauthorized({ error } : HttpErrorResponse) {
    this.#_messagesService.showError(error.message);
    this.#_storageService.clean();
    this.#_router.navigate(['/auth/login']);
  }

  private _handleNotFound() {
    this.#_messagesService.showError('Recurso não encontrado. Status: 404');
    console.error('Recurso não encontrado. Status: 404');
  }

  private _handleServerError() {
    this.#_messagesService.showError('Erro interno do servidor. Status: 500');
    console.error('Erro interno do servidor. Status: 500');
  }

  private _handleUnknownError(status: number) {
    this.#_messagesService.showError(`Erro não tratado. Status: ${status}`);
    console.error('Erro não tratado. Status:', status);
  }
}
