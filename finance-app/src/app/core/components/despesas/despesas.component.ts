import { Component, OnInit } from '@angular/core';
import { BaseTransacaoDirective } from '../../directives/base-transacao.directive';

@Component({
  selector: 'fin-despesas',
  templateUrl: './despesas.component.html',
  styleUrl: './despesas.component.scss',
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
