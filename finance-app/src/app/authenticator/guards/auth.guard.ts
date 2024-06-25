import { inject } from "@angular/core";
import { CanActivateFn, Router } from "@angular/router";
import { StorageService } from "../../core/services/storage.service";

export const authGuard: CanActivateFn = (): boolean => {
  const storageService = inject(StorageService);
  const router = inject(Router);

  const authRoutes = router.url.includes("/auth");

  const currentUser = storageService.isLoggedIn();
  if (currentUser || authRoutes) {
    return true;
  }

  storageService.clean();
  router.navigate(["/auth/login"]);
  return false;
};
