import { Component, OnInit } from '@angular/core';
import { BaseTransacaoDirective } from '../../directives/base-transacao.directive';
import { WrapContainerComponent } from '../wrap-container/wrap-container.component';
import { TransacaoTableComponent } from '../transacao-table/transacao-table.component';
import { AlertContainerComponent } from '../alert-container/alert-container.component';

@Component({
    selector: 'coinz-despesas',
    templateUrl: './despesas.component.html',
    styleUrl: './despesas.component.scss',
    standalone: true,
    imports: [
        WrapContainerComponent,
        TransacaoTableComponent,
        AlertContainerComponent,
    ],
})
export class DespesasComponent
  extends BaseTransacaoDirective
  implements OnInit
{
  override ngOnInit(): void {
    this.queryParams().idTipoTransacao = 2;
    super.ngOnInit();
  }
}
