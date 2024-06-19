import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { CategoriasComponent } from './components/categorias/categorias.component';
import { DespesasComponent } from './components/despesas/despesas.component';
import { MainComponent } from './components/main/main.component';
import { ReceitasComponent } from './components/receitas/receitas.component';
import { HomeComponent } from './pages/home/home.component';
import { authGuard } from '../authenticator/guards/auth.guard';

const routes: Routes = [
  {
    path: '',
    component: HomeComponent,
    canActivateChild: [authGuard],
    children: [
      { path: 'all', component: MainComponent },
      { path: 'entradas', component: ReceitasComponent },
      { path: 'saidas', component: DespesasComponent },
      { path: 'categorias', component: CategoriasComponent },
      { path: '', redirectTo: 'all', pathMatch: 'full' },
    ],
  },
];

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class CoreRoutingModule { }
