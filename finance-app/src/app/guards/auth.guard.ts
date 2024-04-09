import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../authenticator/services/auth.service';

export const authGuard: CanActivateFn = (route, state): boolean => {
  const authService = inject(AuthService);
  const router = inject(Router);

  const currentUser = authService.isLoggedIn();
  if (currentUser) {
    return true;
  }
  
  router.navigate(['/login']);
  return false;
};
