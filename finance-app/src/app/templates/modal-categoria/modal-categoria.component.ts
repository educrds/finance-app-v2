import { Component, OnInit } from '@angular/core';
import { CategoriasService } from '../../services/categorias.service';
import { FormBuilder, FormControl, FormGroup } from '@angular/forms';
import { NotificationService } from '../../services/notification.service';
import { DynamicDialogConfig, DynamicDialogRef } from 'primeng/dynamicdialog';
import { Categoria } from '../../interfaces/Categorias';

@Component({
  selector: 'fin-modal-categoria',
  templateUrl: './modal-categoria.component.html',
  styleUrl: './modal-categoria.component.scss',
})
export class ModalCategoriaComponent implements OnInit {
  formAddCategoria!: FormGroup;

  protected loading: boolean = false;

  constructor(
    private _categoriaService: CategoriasService,
    private _fb: FormBuilder,
    private _notificationService: NotificationService,
    private ref: DynamicDialogRef,
    private config: DynamicDialogConfig
  ) {}

  ngOnInit(): void {
    if (this.config.data.cat_id) {
      this.formAddCategoria = this._fb.group({
        cat_id: [this.config.data.cat_id],
        cat_nome: [this.config.data.cat_nome],
        usr_id: [this.config.data.usr_id],
        cat_cor: [this.config.data.cat_cor],
      });
    } else {
      this.formAddCategoria = this._fb.group({
        cat_nome: [''],
        cat_cor: [''],
      });
    }
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
    this._categoriaService.addCategoria(form).subscribe({
      next: () => {
        this._notificationService.showSuccess(
          'Categoria inserida com sucesso!'
        );
        this.ref.close();
      },
      error: () =>
        this._notificationService.showError(
          'Ocorreu um erro ao adicionar categoria!'
        ),
      complete: () => (this.loading = false),
    });
  }

  private _atualizarCategoria(form: Categoria) {
    this._categoriaService.atualizarCategoria(form).subscribe({
      next: () => {
        this._notificationService.showSuccess(
          'Categoria atualizada com sucesso!'
        );
        this.ref.close();
      },
      error: () =>
        this._notificationService.showError(
          'Ocorreu um erro ao atualizar categoria!'
        ),
      complete: () => (this.loading = false),
    });
  }
}
