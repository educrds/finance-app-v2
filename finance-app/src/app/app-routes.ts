import { Routes } from '@angular/router';

// Components
import { loggedInGuard } from './guards/logged-in.guard';
import { authGuard } from './authenticator/guards/auth.guard';


export const APP_ROUTES: Routes = [
  {
    path: '',
    loadComponent: () => import('./core/pages/home/home.component').then(m => m.HomeComponent),
    loadChildren: () => import('./core/core-routes').then(m => m.CORE_ROUTES),
    canActivate: [authGuard],
  },
  {
    path: 'auth',
    loadChildren: () => import('./authenticator/auth-routes').then(m => m.AUTH_ROUTES),
    canActivate: [loggedInGuard],
  },
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
  { path: '**', redirectTo: '/dashboard' },
];
