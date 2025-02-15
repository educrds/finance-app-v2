import { Component, inject, input, OnInit } from '@angular/core';
import { MenuItem } from 'primeng/api';
import { DynamicDialogRef, DialogService } from 'primeng/dynamicdialog';
import { SplitButton } from 'primeng/splitbutton';
import { ModalTransacaoComponent } from '../../../core/templates/modal-transacao/modal-transacao.component';

@Component({
  selector: 'coinz-table-header',
  standalone: true,
  imports: [SplitButton],
  templateUrl: './table-header.component.html',
  styleUrl: './table-header.component.scss'
})
export class TableHeaderComponent implements OnInit {
  public title = input.required<string>();

  protected items_transacao: MenuItem[] = [];
  private _ref: DynamicDialogRef | undefined;
  
  #_dialogService = inject(DialogService);

  ngOnInit(): void {
    this.setupItemsMenuTransacao();
  }

  private setupItemsMenuTransacao(): void {
    this.items_transacao = [
      {
        label: "Entradas",
        command: () => this.openModalAdd(1),
      },
      {
        label: "Saídas",
        command: () => this.openModalAdd(2),
      },
    ];
  }

    protected openModalAdd(trs_tipo: number) {
      const header = trs_tipo === 1 ? "Nova Receita" : "Nova Despesa";
  
      this._ref = this.#_dialogService.open(ModalTransacaoComponent, {
        modal: true,
        header: header,
        closable: true,
        contentStyle: { overflow: "auto" },
        data: {
          id_tipo_transacao: trs_tipo,
        },
      });
    }
}
