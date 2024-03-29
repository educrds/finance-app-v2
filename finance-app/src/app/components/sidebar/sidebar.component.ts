import { Component, OnInit } from '@angular/core';
import { MenuItem, MessageService } from 'primeng/api';

@Component({
  selector: 'fin-sidebar',
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.scss',
  providers: [MessageService],
})
export class SidebarComponent implements OnInit {
  items_menu: MenuItem[] | undefined;
  items_transacao: MenuItem[] | undefined;

  ngOnInit(): void {
    this.items_menu = [
      {
        label: 'Transações',
        items: [
          {
            label: 'Todas',
            icon: 'pi pi-book',
            command: () => {},
          },
          {
            label: 'Receitas',
            icon: 'pi pi-plus-circle',
            command: () => {},
          },
          {
            label: 'Despesas',
            icon: 'pi pi-minus-circle',
            command: () => {},
          },
        ],
      },
    ];

    this.items_transacao = [
      {
        label: 'Receitas',
        icon: 'pi pi-plus-circle',
        command: () => {},
      },
      {
        label: 'Despesas',
        icon: 'pi pi-minus-circle',
        command: () => {},
      },
    ];
  }
}
