import { Component, OnInit, ViewChild } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { TransacaoUtilService } from '../../utils/transacao-util.service';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';
import { NotificationService } from '../../shared/services/notification.service';
import { Table } from 'primeng/table';
import { BaseTransacaoComponent } from '../../shared/components/base-transacao/base-transacao.component';

@Component({
  selector: 'fin-receitas',
  templateUrl: './receitas.component.html',
  styleUrl: './receitas.component.scss',
})
export class ReceitasComponent
  extends BaseTransacaoComponent
  implements OnInit {
    override ngOnInit(): void {
      this.queryParams.idTipoTransacao = 1;
      super.ngOnInit()
    }
  }
