import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

// Components
import { HomeComponent } from './pages/home/home.component';
import { MainComponent } from './components/main/main.component';
import { ReceitasComponent } from './components/receitas/receitas.component';
import { DespesasComponent } from './components/despesas/despesas.component';
import { CategoriasComponent } from './components/categorias/categorias.component';
import { LoginComponent } from './authenticator/pages/login/login.component';
import { authGuard } from './authenticator/guards/auth.guard';
import { RegisterComponent } from './authenticator/pages/register/register.component';
import { loggedInGuard } from './guards/logged-in.guard';

const routes: Routes = [
  {
    path: '',
    component: HomeComponent,
    canActivate: [authGuard],
    children: [
      { path: 'all', component: MainComponent },
      { path: 'entradas', component: ReceitasComponent },
      { path: 'saidas', component: DespesasComponent },
      { path: 'categorias', component: CategoriasComponent },
      { path: '', redirectTo: '/all', pathMatch: 'full' },
    ],
  },
  {
    path: 'login',
    component: LoginComponent,
    canActivate: [loggedInGuard],
    children: [],
  },
  {
    path: 'register',
    component: RegisterComponent,
    canActivate: [loggedInGuard],
    children: [],
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
