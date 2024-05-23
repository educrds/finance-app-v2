import { Component, EventEmitter, Input, Output, WritableSignal, inject, signal } from '@angular/core';
import { Categoria, Categorias } from '../../../interfaces/Categorias';
import { ConfirmationService } from 'primeng/api';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { CategoriasService } from '../../../services/categorias.service';
import { MessagesService } from '../../../services/messages.service';
import { ModalCategoriaComponent } from '../../../templates/modal-categoria/modal-categoria.component';

@Component({
  selector: 'fin-categoria-table',
  templateUrl: './categoria-table.component.html',
  styleUrl: './categoria-table.component.scss'
})
export class CategoriaTableComponent {
  @Input() categorias: WritableSignal<Categorias[]> = signal([]);
  @Input() configModal: any;
  @Output() isCategoriaDeleted = new EventEmitter<boolean>();

  private _confirmationService = inject(ConfirmationService);
  private _messagesService = inject(MessagesService);
  private _dialogService = inject(DialogService);
  private _categoriasService = inject(CategoriasService);

  private ref!: DynamicDialogRef;

  // Metódo responsavel por deletar uma categoria
  protected deletarCategoria(form: Categoria) {
    this._confirmationService.confirm({
      message: 'Deseja realmente excluir o registro? <br> Esta ação é irreversível.',
      header: 'Confirmação',
      icon: 'pi pi-exclamation-triangle',
      acceptIcon: 'none',
      rejectIcon: 'none',
      rejectButtonStyleClass: 'p-button-text',
      accept: () => {
        this._categoriasService.deletarCategoria(form).subscribe({
          next: () => {
            this._messagesService.showSuccess('Registro deletado com sucesso!');
            this.isCategoriaDeleted.emit(true)
          },
          error: () => this._messagesService.showError('Ocorreu um erro ao deletar registro, tente novamente!'),
        });
      },
    });
  }
  
  // Metódo responsavel por editar uma categoria
  protected editarCategoria(categoria: Categoria) {
    this.ref = this._dialogService.open(ModalCategoriaComponent, {
      ...this.configModal,
      data: categoria,
    });
  }
}
