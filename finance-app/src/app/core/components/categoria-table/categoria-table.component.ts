import {
  ChangeDetectionStrategy,
  Component,
  inject,
  input,
  output,
} from '@angular/core';
import { Categoria, Categorias } from '../../models/Categorias';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { CategoriasService } from '../../services/categorias.service';
import { MessagesService } from '../../services/messages.service';
import { ModalCategoriaComponent } from '../../templates/modal-categoria/modal-categoria.component';

@Component({
  selector: 'fin-categoria-table',
  templateUrl: './categoria-table.component.html',
  styleUrl: './categoria-table.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class CategoriaTableComponent {
  public configModal = input();
  public categorias = input<Categorias[]>([]);
  public isCategoriaDeleted = output<boolean>();

  // dependencias
  private _messagesService = inject(MessagesService);
  private _dialogService = inject(DialogService);
  private _categoriasService = inject(CategoriasService);

  private _ref!: DynamicDialogRef;

  // Metódo responsavel por deletar uma categoria
  protected deletarCategoria(form: Categoria) {
    this._messagesService.confirm(
      'Deseja realmente excluir o registro? <br> Esta ação é irreversível.',
      'Confirmação',
      () => {
        this._categoriasService.deletarCategoria$(form).subscribe({
          next: () => {
            this._messagesService.showSuccess('Registro deletado com sucesso!');
            this.isCategoriaDeleted.emit(true);
          },
          error: () => this._messagesService.showError('Ocorreu um erro ao deletar registro, tente novamente!'),
        });
      }
    );
  }

  // Metódo responsavel por editar uma categoria
  protected editarCategoria(categoria: Categoria) {
    this._ref = this._dialogService.open(ModalCategoriaComponent, {
      ...this.configModal,
      data: categoria,
    });
  }
}
