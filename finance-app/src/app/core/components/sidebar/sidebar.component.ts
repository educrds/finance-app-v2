import { Component, OnInit, inject } from '@angular/core';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalTransacaoComponent } from '../../templates/modal-transacao/modal-transacao.component';
import { WrapContainerComponent } from '../wrap-container/wrap-container.component';
import { SplitButton } from 'primeng/splitbutton';
import { Menu } from 'primeng/menu';
import { MenuItem } from 'primeng/api';


@Component({
    selector: 'fin-sidebar',
    templateUrl: './sidebar.component.html',
    styleUrl: './sidebar.component.scss',
    standalone: true,
    imports: [
        WrapContainerComponent,
        SplitButton,
        Menu,
    ],
})
export class SidebarComponent implements OnInit {
  // incompatibilidade entre tipos do fontAwesome e tipagem do MenuItem.
  protected items_menu: MenuItem[] = [];
  protected items_transacao: MenuItem[] = [];

  #ref: DynamicDialogRef | undefined;

  #dialogService = inject(DialogService);

  ngOnInit(): void {
    this.items_menu = [
      {
        label: 'Transações',
        items: [
          {
            label: 'Dashboard',
            routerLink: '/dashboard',
          },
          {
            label: 'Entradas',
            routerLink: '/entradas',
          },
          {
            label: 'Saídas',
            routerLink: '/saidas',
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
            routerLink: '/categorias',
          },
        ],
      },
    ];

    this.items_transacao = [
      {
        label: 'Entradas',
        command: () => this.openModalAdd(1)
      },
      {
        label: 'Saídas',
        command: () => this.openModalAdd(2)
      },
    ];
  }

  protected openModalAdd(trs_tipo: number){
    const header = trs_tipo === 1 ? 'Nova Receita' : 'Nova Despesa';

    this.#ref = this.#dialogService.open(ModalTransacaoComponent, {
      modal: true,
      header: header,
      closable: true,
      width: '40vw',
      contentStyle: { overflow: 'auto' },
      data: {
        id_tipo_transacao: trs_tipo
      }
    });
  }
}
