import { Component, OnInit } from '@angular/core';
import { BaseTransacaoDirective } from '../../directives/base-transacao.directive';
import { ColumnComponent } from '../../../shared/components/column/column.component';
import { WrapContainerComponent } from '../wrap-container/wrap-container.component';
import { TransacaoTableComponent } from '../transacao-table/transacao-table.component';
import { AlertContainerComponent } from '../alert-container/alert-container.component';
import { TableHeaderComponent } from "../../../shared/components/table-header/table-header.component";

@Component({
    selector: 'coinz-receitas',
    templateUrl: './receitas.component.html',
    styleUrl: './receitas.component.scss',
    standalone: true,
    imports: [
    ColumnComponent,
    WrapContainerComponent,
    TransacaoTableComponent,
    AlertContainerComponent,
    TableHeaderComponent
],
})
export class ReceitasComponent
  extends BaseTransacaoDirective
  implements OnInit {
    override ngOnInit(): void {
      this.queryParams().idTipoTransacao = 1;
      super.ngOnInit()
    }
  }
