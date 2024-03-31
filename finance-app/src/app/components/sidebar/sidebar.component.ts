import { Component, OnInit } from '@angular/core';
import { MenuItem } from 'primeng/api';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalTransacaoComponent } from '../modal-transacao/modal-transacao.component';

@Component({
  selector: 'fin-sidebar',
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.scss',
  providers: [DialogService],
})
export class SidebarComponent implements OnInit {
  items_menu: MenuItem[] | undefined;
  items_transacao: MenuItem[] | undefined;

  ref: DynamicDialogRef | undefined;

  constructor(private dialogService: DialogService) {}

  ngOnInit(): void {
    this.items_menu = [
      {
        label: 'Transações',
        items: [
          {
            label: 'Ver todas',
            icon: 'pi pi-book',
            routerLink: ['/all'],
          },
          {
            label: 'Receitas',
            icon: 'pi pi-plus-circle',
            routerLink: ['/receitas'],
          },
          {
            label: 'Despesas',
            icon: 'pi pi-minus-circle',
            routerLink: ['/despesas'],
          },
        ],
      },
      {
        separator: true,
      },
      {
        label: 'Categorias',
        items: [
          {
            label: 'Ver todas',
            icon: 'pi pi-book',
          },
        ],
      },
    ];

    this.items_transacao = [
      {
        label: 'Receitas',
        icon: 'pi pi-plus-circle',
        command: () => {
          this.ref = this.dialogService.open(ModalTransacaoComponent, {
            modal: true,
            header: 'Nova Receita',
            width: '35vw',
            contentStyle: { overflow: 'auto' },
            data: {
              trs_tipo: 1
            }
          });
        },
      },
      {
        label: 'Despesas',
        icon: 'pi pi-minus-circle',
        command: () => {
          this.ref = this.dialogService.open(ModalTransacaoComponent, {
            modal: true,
            header: 'Nova Despesa',
            width: '35vw',
            contentStyle: { overflow: 'auto' },
            data: {
              trs_tipo: 2
            }
          });
        },
      },
    ];
  }

}
