import { Component, OnInit } from '@angular/core';
import { CategoriasService } from '../../services/categorias.service';
import { Categoria, Categorias } from '../../interfaces/Categorias';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalCategoriaComponent } from '../../templates/modal-categoria/modal-categoria.component';
import { ConfirmationService } from 'primeng/api';
import { MessagesService } from '../../services/messages.service';
import { NotificationService } from '../../shared/services/notification.service';

@Component({
  selector: 'fin-categorias',
  templateUrl: './categorias.component.html',
  styleUrl: './categorias.component.scss',
})
export class CategoriasComponent implements OnInit {
  protected categorias!: Categorias[];
  private _configModal = {
    modal: true,
    header: 'Atualizar Categoria',
    width: '35vw',
    contentStyle: { overflow: 'auto' },
  };
  ref!: DynamicDialogRef;

  constructor(
    private _notificationService: NotificationService,
    private _categoriasService: CategoriasService,
    private _messagesService: MessagesService,
    private _dialogService: DialogService,
    private _confirmationService: ConfirmationService,
  ) {}

  ngOnInit(): void {
    this.getCategoriasList();
    this._notificationService.notifyObservable$.subscribe(
      (res) => res.refresh && this.getCategoriasList()
    );
  }
  
  getCategoriasList(){
    this._categoriasService.getCategorias().subscribe({
      next: (res) => (this.categorias = res),
      error: () =>
        this._messagesService.showError(
          'Erro ao obter categorias. Tente novamente.'
        ),
    });
  }
  
  protected abrirModalAddCategoria() {
    this.ref = this._dialogService.open(ModalCategoriaComponent, {
      ...this._configModal,
      data: {},
    });
  }

  protected deletarCategoria(form: Categoria) {
    this._confirmationService.confirm({
      message:
        'Deseja realmente excluir o registro? <br> Esta ação é irreversível.',
      header: 'Confirmação',
      icon: 'pi pi-exclamation-triangle',
      acceptIcon: 'none',
      rejectIcon: 'none',
      rejectButtonStyleClass: 'p-button-text',
      accept: () => {
        this._categoriasService.deletarCategoria(form).subscribe({
          next: () => {
            this._messagesService.showSuccess(
              'Registro deletado com sucesso!'
            );
            this.ngOnInit();
          },
          error: () =>
            this._messagesService.showError(
              'Ocorreu um erro ao deletar registro, tente novamente!'
            ),
        });
      },
    });
  }

  protected editarCategoria(categoria: Categoria) {
    this.ref = this._dialogService.open(ModalCategoriaComponent, {
      ...this._configModal,
      data: categoria,
    });
  }
}