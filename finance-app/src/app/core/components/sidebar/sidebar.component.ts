import { Component, OnInit, inject } from '@angular/core';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalTransacaoComponent } from '../../templates/modal-transacao/modal-transacao.component';
import { faChartSimple, faLevelDownAlt, faLevelUpAlt, faList } from '@fortawesome/free-solid-svg-icons';
import { Icon } from '../../models/Icon';

@Component({
  selector: 'fin-sidebar',
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.scss',
})
export class SidebarComponent implements OnInit {
  private iconsSidebar: Icon = {
    dashboard: faChartSimple,
    entrada: faLevelUpAlt,
    saida: faLevelDownAlt,
    categorias: faList,
  }

  // incompatibilidade entre tipos do fontAwesome e tipagem do MenuItem.
  protected items_menu!: any[];
  protected items_transacao!: any[];

  #ref: DynamicDialogRef | undefined;

  #dialogService = inject(DialogService);

  ngOnInit(): void {
    this.items_menu = [
      {
        label: 'Transações',
        items: [
          {
            label: 'Dashboard',
            icon: this.iconsSidebar['dashboard'],
            route: '/dashboard',
            routerLinkActiveOptions: { exact: true }
          },
          {
            label: 'Entradas',
            icon: this.iconsSidebar['entrada'],
            route: '/entradas',
            routerLinkActiveOptions: { exact: true }
          },
          {
            label: 'Saídas',
            icon: this.iconsSidebar['saida'],
            route: '/saidas',
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
            icon: this.iconsSidebar['categorias'],
            route: '/categorias',
            routerLinkActiveOptions: { exact: true }
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
      width: '40vw',
      contentStyle: { overflow: 'auto' },
      data: {
        id_tipo_transacao: trs_tipo
      }
    });
  }
}
