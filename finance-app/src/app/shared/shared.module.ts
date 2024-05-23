import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AlertContainerComponent } from './components/alert-container/alert-container.component';
import { ColumnComponent } from './components/column/column.component';
import { LogoComponent } from './components/logo/logo.component';
import { RowComponent } from './components/row/row.component';
import { TopCardComponent } from './components/top-card/top-card.component';
import { WrapContainerComponent } from './components/wrap-container/wrap-container.component';
import { BaseTransacaoDirective } from './directives/base-transacao.directive';
import { TransacaoTableComponent } from './components/transacao-table/transacao-table.component';
import { TableModule } from 'primeng/table';
import { TooltipModule } from 'primeng/tooltip';
import { ButtonModule } from 'primeng/button';
import { InputTextModule } from 'primeng/inputtext';
import { CategoriaTableComponent } from './components/categoria-table/categoria-table.component';
import { TagModule } from 'primeng/tag';
@NgModule({
  declarations: [
    AlertContainerComponent,
    ColumnComponent,
    LogoComponent,
    RowComponent,
    TopCardComponent,
    WrapContainerComponent,
    BaseTransacaoDirective,
    TransacaoTableComponent,
    CategoriaTableComponent,
  ],
  exports: [
    AlertContainerComponent,
    ColumnComponent,
    LogoComponent,
    RowComponent,
    TopCardComponent,
    WrapContainerComponent,
    TransacaoTableComponent,
    CategoriaTableComponent
  ],
  imports: [CommonModule, TableModule, TooltipModule, ButtonModule, InputTextModule, TagModule]
})
export class SharedModule {}
