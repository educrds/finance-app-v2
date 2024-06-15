import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

// Components
import { loggedInGuard } from './guards/logged-in.guard';
import { authGuard } from './authenticator/guards/auth.guard';

const routes: Routes = [
  {
    path: '',
    loadChildren: () => import('./core/core.module').then(m => m.CoreModule),
    canActivate: [authGuard],
  },
  {
    path: 'auth',
    loadChildren: () => import('./authenticator/auth.module').then(m => m.AuthModule),
    canActivate: [loggedInGuard],
  },
  { path: '', redirectTo: '', pathMatch: 'full' },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
