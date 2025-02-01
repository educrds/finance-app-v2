import { Component, inject, OnInit, signal, WritableSignal } from "@angular/core";
import { CategoriasService } from "../../services/categorias.service";
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from "@angular/forms";
import { DynamicDialogConfig, DynamicDialogRef } from "primeng/dynamicdialog";
import { Categoria } from "../../models/Categorias";
import { IDropdown } from "../../models/Dropdown";
import { MessagesService } from "../../services/messages.service";
import { NotificationService } from "../../services/notification.service";
import { finalize } from "rxjs";
import { ColumnComponent } from "../../../shared/components/column/column.component";
import { InputFormComponent } from "../../components/input-form/input-form.component";
import { Select } from "primeng/select";
import { ColorPickerModule } from "primeng/colorpicker";
import { Button } from "primeng/button";

@Component({
  selector: "fin-modal-categoria",
  templateUrl: "./modal-categoria.component.html",
  styleUrl: "./modal-categoria.component.scss",
  standalone: true,
  imports: [
    FormsModule,
    ReactiveFormsModule,
    ColumnComponent,
    InputFormComponent,
    Select,
    ColorPickerModule,
    Button,
  ],
})
export class ModalCategoriaComponent implements OnInit {
  protected formAddCategoria!: FormGroup;
  protected tipoOptions: IDropdown[] = [
    { id: 1, text: "Receita" },
    { id: 2, text: "Despesa" },
  ];

  protected isLoading: WritableSignal<boolean> = signal(false);

  private _fb = inject(FormBuilder);
  private _ref = inject(DynamicDialogRef);
  private _categoriaService = inject(CategoriasService);
  private _messagesService = inject(MessagesService);
  private _notificationService = inject(NotificationService);
  private _config = inject(DynamicDialogConfig);

  ngOnInit(): void {
    this.formAddCategoria = this._fb.group({
      cat_id: [this._config.data.cat_id || null],
      cat_nome: [this._config.data.cat_nome || null, Validators.required],
      cat_cor: [this._config.data.cat_cor || null, Validators.required],
      usr_id: [this._config.data.usr_id || null],
      cat_tip_id: [this._config.data.cat_tip_id || null],
    });
  }

  protected inserirOuAtualizarCategoria(): void {
    this.isLoading.set(false);
    const form = this.formAddCategoria.getRawValue();

    if (form.cat_id) {
      return this._atualizarCategoria(form);
    }
    this._inserirCategoria(form);
  }

  private _inserirCategoria(form: Categoria) {
    if (this.formAddCategoria.valid) {
      return this._categoriaService
        .addCategoria$(form)
        .pipe(finalize(() => (this.isLoading.set(false))))
        .subscribe(response => this._handleCategoria(response));
    }
    return this.updateValidationForm(this.formAddCategoria);
  }

  private _handleCategoria(categoriaResponse: { "message": string }): void {
    this._messagesService.showSuccess(categoriaResponse["message"]);
    this._ref.close();
    this._notificationService.notifyChanges({ refresh: true });
  }

  private updateValidationForm(group: FormGroup): void {
    group.markAllAsTouched();
    Object.keys(group.controls).map((key: string) => {
      const abstractControl = group.controls[key];
      abstractControl.updateValueAndValidity();
    });
  }

  private _atualizarCategoria(form: Categoria): void {
    this._categoriaService
      .atualizarCategoria$(form)
      .pipe(finalize(() => (this.isLoading.set(false))))
      .subscribe(response => this._handleCategoria(response));
  }
}
