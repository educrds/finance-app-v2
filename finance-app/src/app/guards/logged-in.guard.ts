import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { StorageService } from '../core/services/storage.service';
import { CustomMessageService } from '../core/services/custom-message.service';

export const loggedInGuard: CanActivateFn = () => {
  const storageService = inject(StorageService);
  const router = inject(Router);
  const messagesService = inject(CustomMessageService);

  if(storageService.isLoggedIn()){
    messagesService.showError("Você já está autenticado.");
    return router.navigate(['/dashboard']);
  }
  return true;
};
