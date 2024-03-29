import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
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

  constructor(private router: Router){}

  ngOnInit(): void {
    this.items_menu = [
      {
        label: 'Transações',
        items: [
          {
            label: 'Ver todas',
            icon: 'pi pi-book',
            command: () => {
              this.router.navigate(['all'])
            },
          },
          {
            label: 'Receitas',
            icon: 'pi pi-plus-circle',
            command: () => {
              this.router.navigate(['receitas'])
            },
          },
          {
            label: 'Despesas',
            icon: 'pi pi-minus-circle',
            command: () => {
              this.router.navigate(['despesas'])
            },
          },
        ],
      },
      {
        separator: true
      },
      {
        label: 'Categorias',
        items: [
          {
            label: 'Ver todas',
            icon: 'pi pi-book',
            command: () => {},
          }
        ]     
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
