import { Component, OnInit } from '@angular/core';
import { BaseTransacaoDirective } from '../../shared/directives/base-transacao.directive';

@Component({
  selector: 'fin-receitas',
  templateUrl: './receitas.component.html',
  styleUrl: './receitas.component.scss',
})
export class ReceitasComponent
  extends BaseTransacaoDirective
  implements OnInit {
    override ngOnInit(): void {
      this.queryParams().idTipoTransacao = 1;
      super.ngOnInit()
    }
  }
