import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

// Components
import { HomeComponent } from './pages/home/home.component';
import { MainComponent } from './components/main/main.component';
import { ReceitasComponent } from './components/receitas/receitas.component';
import { DespesasComponent } from './components/despesas/despesas.component';
import { CategoriasComponent } from './components/categorias/categorias.component';
import { authGuard } from './authenticator/guards/auth.guard';
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
    path: 'auth',
    loadChildren: () => import('./authenticator/auth.module').then(m => m.AuthModule),
    canActivate: [loggedInGuard]
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
