import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { StorageService } from '../core/services/storage.service';
import { MessagesService } from '../core/services/messages.service';

export const loggedInGuard: CanActivateFn = () => {
  const storageService = inject(StorageService);
  const router = inject(Router);
  const messagesService = inject(MessagesService);

  if(storageService.isLoggedIn()){
    messagesService.showError("Você já está autenticado.");
    return router.navigate(['/dashboard']);
  }
  return true;
};
