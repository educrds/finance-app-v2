import { Component, OnInit, inject } from "@angular/core";
import { DialogService, DynamicDialogRef } from "primeng/dynamicdialog";
import { ModalTransacaoComponent } from "../../templates/modal-transacao/modal-transacao.component";
import { WrapContainerComponent } from "../wrap-container/wrap-container.component";
import { SplitButton } from "primeng/splitbutton";
import { Menu } from "primeng/menu";
import { MenuItem } from "primeng/api";

@Component({
  selector: "fin-sidebar",
  templateUrl: "./sidebar.component.html",
  styleUrl: "./sidebar.component.scss",
  standalone: true,
  imports: [WrapContainerComponent, SplitButton, Menu],
})
export class SidebarComponent implements OnInit {
  protected items_menu: MenuItem[] = [];
  protected items_transacao: MenuItem[] = [];

  private _ref: DynamicDialogRef | undefined;

  private _dialogService = inject(DialogService);

  ngOnInit(): void {
    this.setupItemsMenu();
    this.setupItemsMenuTransacao();
  }

  private setupItemsMenu(): void {
    this.items_menu = [
      {
        label: "Dashboard",
        routerLink: "/dashboard",
        icon: "pi pi-chart-pie",
      },
      {
        label: "Entradas",
        routerLink: "/entradas",
        icon: "pi pi-arrow-up-right",
      },
      {
        label: "Saídas",
        routerLink: "/saidas",
        icon: "pi pi-arrow-down-left",
      },
      {
        separator: true,
      },
      {
        label: "Categorias",
        routerLink: "/categorias",
        icon: "pi pi-align-justify",
      },
    ];
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

    this._ref = this._dialogService.open(ModalTransacaoComponent, {
      modal: true,
      header: header,
      closable: true,
      width: "40vw",
      contentStyle: { overflow: "auto" },
      data: {
        id_tipo_transacao: trs_tipo,
      },
    });
  }
}
