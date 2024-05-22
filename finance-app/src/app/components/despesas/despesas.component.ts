import { Component, OnInit } from '@angular/core';
import { BaseTransacaoComponent } from '../../shared/components/base-transacao/base-transacao.component';

@Component({
  selector: 'fin-despesas',
  templateUrl: './despesas.component.html',
  styleUrl: './despesas.component.scss',
})
export class DespesasComponent
  extends BaseTransacaoComponent
  implements OnInit
{
  override ngOnInit(): void {
    this.queryParams.idTipoTransacao = 2;
    super.ngOnInit();
  }
}
