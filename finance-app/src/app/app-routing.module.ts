import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './pages/home/home.component';
import { MainComponent } from './components/main/main.component';
import { ReceitasComponent } from './components/receitas/receitas.component';
import { DespesasComponent } from './components/despesas/despesas.component';

const routes: Routes = [
  {
    path: '',
    component: HomeComponent,
    children: [
      { path: 'all', component:  MainComponent},
      { path: 'receitas', component:  ReceitasComponent},
      { path: 'despesas', component:  DespesasComponent},
    ]
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
