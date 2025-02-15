import { Component, OnInit, WritableSignal, inject, signal } from "@angular/core";
import { CategoriasService } from "../../services/categorias.service";
import { Categorias } from "../../models/Categorias";
import { DialogService, DynamicDialogRef } from "primeng/dynamicdialog";
import { ModalCategoriaComponent } from "../../templates/modal-categoria/modal-categoria.component";
import { Observable, startWith, switchMap } from "rxjs";
import { NotificationService } from "../../services/notification.service";
import { WrapContainerComponent } from "../wrap-container/wrap-container.component";
import { Button } from "primeng/button";
import { AsyncPipe } from "@angular/common";
import { Menu } from "primeng/menu";
import { MenuItem } from "primeng/api";
import { MessagesService } from "../../services/messages.service";

@Component({
  selector: "fin-categorias",
  templateUrl: "./categorias.component.html",
  styleUrl: "./categorias.component.scss",
  standalone: true,
  imports: [WrapContainerComponent, Button, Menu, AsyncPipe],
})
export class CategoriasComponent implements OnInit {
  private _ref!: DynamicDialogRef;

  #_categoriasService = inject(CategoriasService);
  #_dialogService = inject(DialogService);
  #_notificationService = inject(NotificationService);

  protected selectedCategoria: WritableSignal<Categorias | null> = signal(null);
  protected items_categoria: MenuItem[] = [];
  protected categorias$!: Observable<Categorias[]>;
  protected configModal = {
    modal: true,
    header: "Nova Categoria",
    closable: true,
    contentStyle: { overflow: "auto" },
  };

  private _messagesService = inject(MessagesService);
  private _dialogService = inject(DialogService);
  private _categoriasService = inject(CategoriasService);

  ngOnInit(): void {
    this.categorias$ = this.#_notificationService.notifyObservable$.pipe(
      startWith({ refresh: true }),
      switchMap(res => (res.refresh ? this.#_categoriasService.getCategoriasByUser$() : []))
    );

    this.items_categoria = [
      {
        label: "Editar",
        command: () => this.editarCategoria(this.selectedCategoria()),
      },
      {
        label: "Excluir",
        command: () => this.deletarCategoria(this.selectedCategoria()),
      },
    ];
  }

  protected openMenu(event: MouseEvent, categoria: Categorias, menu: Menu) {
    this.selectedCategoria.set(categoria);
    menu.toggle(event);
  }
  
  // Metódo responsavel por deletar uma categoria
  protected deletarCategoria(form: Categorias | null) {
    this._messagesService.confirm(
      "Deseja realmente excluir o registro? <br> Esta ação é irreversível.",
      "Confirmação",
      () => {
        this._categoriasService.deletarCategoria$(form).subscribe({
          next: res => {
            this._messagesService.showSuccess(res["message"]);
            this.ngOnInit();
          },
          error: () => this._messagesService.showError("Ocorreu um erro ao deletar registro, tente novamente!"),
        });
      }
    );
  }

  // Metódo responsavel por editar uma categoria
  protected editarCategoria(categoria: Categorias | null) {
    this._ref = this._dialogService.open(ModalCategoriaComponent, {
      modal: true,
      header: "Atualizar Categoria",
      closable: true,
      contentStyle: { overflow: "auto" },
      data: categoria,
    });
  }

  // Metódo responsavel por abrir modal de categoria
  protected abrirModalAddCategoria(): void {
    this._ref = this.#_dialogService.open(ModalCategoriaComponent, {
      ...this.configModal,
      data: {},
    });
  }
}
