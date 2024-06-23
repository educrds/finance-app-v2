import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Router } from '@angular/router';
import { throwError } from 'rxjs';
import { MessagesService } from '../../core/services/messages.service';
import { StorageService } from './storage.service';

@Injectable({
  providedIn: 'root',
})
export class HttpErrorHandlerService {
  #_router = inject(Router);
  #_messagesService= inject(MessagesService);
  #_storageService= inject(StorageService);

  handleHttpError(error: HttpErrorResponse) {
    this.#_messagesService.showError(error.error.message);
    if (error.status === 401) {
      // Se a resposta for 401 Unauthorized.
      this.#_storageService.clean();
      this.#_router.navigate(['/auth/login']);
    } else if (error.status === 404) {
      console.error('Recurso não encontrado. Status: 404');
    } else if (error.status === 500) {
      // Trate o erro 500 (Internal Server Error).
      console.error('Erro interno do servidor. Status: 500');
    } else {
      console.error('Erro não tratado. Status:', error.status);
    }
    return throwError(() => new Error("Error ao fazer requisição."));
  }
}
