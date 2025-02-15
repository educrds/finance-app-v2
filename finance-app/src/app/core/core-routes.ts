import { Routes } from '@angular/router';
import { CategoriasComponent } from './components/categorias/categorias.component';
import { DespesasComponent } from './components/despesas/despesas.component';
import { MainComponent } from './components/main/main.component';
import { ReceitasComponent } from './components/receitas/receitas.component';
import { UsersListComponent } from './components/users-list/users-list.component';


export const CORE_ROUTES: Routes = [
  { path: 'dashboard', component: MainComponent },
  { path: 'entradas', component: ReceitasComponent },
  { path: 'saidas', component: DespesasComponent },
  { path: 'categorias', component: CategoriasComponent },
  { path: 'users', component: UsersListComponent },
  { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
]