import { Component, OnInit } from '@angular/core';
import { CategoriasService } from '../../services/categorias.service';
import { Categoria, Categorias } from '../../interfaces/Categorias';
import { NotificationService } from '../../services/notification.service';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalCategoriaComponent } from '../../templates/modal-categoria/modal-categoria.component';
import { ConfirmationService } from 'primeng/api';

@Component({
  selector: 'fin-categorias',
  templateUrl: './categorias.component.html',
  styleUrl: './categorias.component.scss',
  providers: [DialogService, ConfirmationService],
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
    private _categoriasService: CategoriasService,
    private _notificationService: NotificationService,
    private _dialogService: DialogService,
    private _confirmationService: ConfirmationService,
  ) {}

  ngOnInit(): void {
    this.getCategoriasList();
    this._categoriasService.notifyObservable$.subscribe(
      (res) => res.refresh && this.getCategoriasList()
    );
  }
  
  getCategoriasList(){
    this._categoriasService.getCategorias().subscribe({
      next: (res) => (this.categorias = res),
      error: () =>
        this._notificationService.showError(
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
            this._notificationService.showSuccess(
              'Registro deletado com sucesso!'
            );
            this.ngOnInit();
          },
          error: () =>
            this._notificationService.showError(
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