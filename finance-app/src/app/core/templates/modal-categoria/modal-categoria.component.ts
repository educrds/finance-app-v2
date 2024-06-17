import { Component, OnInit } from '@angular/core';
import { CategoriasService } from '../../services/categorias.service';
import { FormBuilder, FormGroup } from '@angular/forms';
import { DynamicDialogConfig, DynamicDialogRef } from 'primeng/dynamicdialog';
import { Categoria } from '../../models/Categorias';
import { IDropdown } from '../../models/Dropdown';
import { MessagesService } from '../../services/messages.service';
import { NotificationService } from '../../../shared/services/notification.service';

@Component({
  selector: 'fin-modal-categoria',
  templateUrl: './modal-categoria.component.html',
  styleUrl: './modal-categoria.component.scss',
})
export class ModalCategoriaComponent implements OnInit {
  formAddCategoria!: FormGroup;
  tipoOptions: IDropdown[] = [
    {
      id: 1,
      text: 'Receita',
    },
    {
      id: 2,
      text: 'Despesa',
    },
  ];

  protected loading: boolean = false;

  constructor(
    private _categoriaService: CategoriasService,
    private _fb: FormBuilder,
    private _messagesService: MessagesService,
    private _notificationService: NotificationService,
    private ref: DynamicDialogRef,
    private config: DynamicDialogConfig
  ) {}

  ngOnInit(): void {
    const defaultCategoriaValues = {
      cat_id: '',
      cat_nome: '',
      usr_id: '',
      cat_cor: '',
      cat_tip_id: '',
    }

    this.formAddCategoria = this._fb.group({
      cat_id: [this.config.data.cat_id || defaultCategoriaValues.cat_id],
      cat_nome: [this.config.data.cat_nome || defaultCategoriaValues.cat_nome],
      usr_id: [this.config.data.usr_id || defaultCategoriaValues.usr_id],
      cat_cor: [this.config.data.cat_cor || defaultCategoriaValues.cat_cor],
      cat_tip_id: [this.config.data.cat_tip_id || defaultCategoriaValues.cat_tip_id ],
    });
  }

  protected inserirOuAtualizarCategoria() {
    this.loading = false;
    const form = this.formAddCategoria.getRawValue();

    if (form.cat_id) {
      this._atualizarCategoria(form);
      return;
    }
    this._inserirCategoria(form);
  }

  private _inserirCategoria(form: Categoria) {
    this._categoriaService.addCategoria$(form).subscribe({
      next: () => {
        this._messagesService.showSuccess('Categoria inserida com sucesso!');
        this.ref.close();
        this._notificationService.notifyChanges({ refresh: true });
      },
      error: ({error}) => this._messagesService.showError(error.message),
      complete: () => this.loading = false
    });
  }

  private _atualizarCategoria(form: Categoria) {
    this._categoriaService.atualizarCategoria$(form).subscribe({
      next: () => {
        this._messagesService.showSuccess('Categoria atualizada com sucesso!');
        this.ref.close();
        this._notificationService.notifyChanges({ refresh: true });
      },
      error: ({error}) => this._messagesService.showError(error.message),
      complete: () => this.loading = false
    });
  }
}
