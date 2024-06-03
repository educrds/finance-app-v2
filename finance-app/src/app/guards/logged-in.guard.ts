import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { StorageService } from '../shared/services/storage.service';
import { MessagesService } from '../services/messages.service';

export const loggedInGuard: CanActivateFn = (route, state) => {
  const storageService = inject(StorageService);
  const router = inject(Router);
  const messagesService = inject(MessagesService);

  if(storageService.isLoggedIn()){
    messagesService.showError("Você já está autenticado.");
    return router.navigate(['/all']);
  }
  return true;
};
