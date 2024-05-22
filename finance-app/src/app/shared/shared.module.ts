import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AlertContainerComponent } from './components/alert-container/alert-container.component';
import { ColumnComponent } from './components/column/column.component';
import { LogoComponent } from './components/logo/logo.component';
import { RowComponent } from './components/row/row.component';
import { TopCardComponent } from './components/top-card/top-card.component';
import { WrapContainerComponent } from './components/wrap-container/wrap-container.component';
import { BaseTransacaoDirective } from './directives/base-transacao.directive';

@NgModule({
  declarations: [
    AlertContainerComponent,
    ColumnComponent,
    LogoComponent,
    RowComponent,
    TopCardComponent,
    WrapContainerComponent,
    BaseTransacaoDirective,
  ],
  exports: [
    AlertContainerComponent,
    ColumnComponent,
    LogoComponent,
    RowComponent,
    TopCardComponent,
    WrapContainerComponent,
  ],
  imports: [CommonModule]
})
export class SharedModule {}
