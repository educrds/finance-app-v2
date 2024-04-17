import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { StorageService } from '../../shared/services/storage.service';

export const authGuard: CanActivateFn = (route, state): boolean => {
  const storageService = inject(StorageService);
  const router = inject(Router);

  const authRoutes = router.url.includes('/login') || router.url.includes('/register');

  const currentUser = storageService.isLoggedIn();
  if (currentUser || authRoutes) {
    return true;
  }

  storageService.clean();
  router.navigate(['/login']);
  return false;
};
