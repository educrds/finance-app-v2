import { Component, OnInit } from '@angular/core';
import { MenuItem } from 'primeng/api';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalTransacaoComponent } from '../../templates/modal-transacao/modal-transacao.component';

@Component({
  selector: 'fin-sidebar',
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.scss',
})
export class SidebarComponent implements OnInit {
  protected items_menu: MenuItem[] | undefined;
  protected items_transacao: MenuItem[] | undefined;

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
            routerLinkActiveOptions: { exact: true }
          },
          {
            label: 'Entradas',
            icon: 'pi pi-arrow-up-right',
            routerLink: ['/entradas'],
            routerLinkActiveOptions: { exact: true }
          },
          {
            label: 'Saídas',
            icon: 'pi pi-arrow-down-right',
            routerLink: ['/saidas'],
            routerLinkActiveOptions: { exact: true }
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
            routerLink: ['/categorias'],
            routerLinkActiveOptions: { exact: true }
          },
        ],
      },
    ];

    this.items_transacao = [
      {
        label: 'Entradas',
        icon: 'pi pi-arrow-up-right',
        command: () => {
          this.ref = this.dialogService.open(ModalTransacaoComponent, {
            modal: true,
            header: 'Nova Receita',
            width: '40vw',
            contentStyle: { overflow: 'auto' },
            data: {
              id_tipo_transacao: 1
            }
          });
        },
      },
      {
        label: 'Saídas',
        icon: 'pi pi-arrow-down-right',
        command: () => {
          this.ref = this.dialogService.open(ModalTransacaoComponent, {
            modal: true,
            header: 'Nova Despesa',
            width: '40vw',
            contentStyle: { overflow: 'auto' },
            data: {
              id_tipo_transacao: 2
            }
          });
        },
      },
    ];
  }

}
