import { Component, OnInit } from "@angular/core";
import { CategoriasService } from "../../services/categorias.service";
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule } from "@angular/forms";
import { DynamicDialogConfig, DynamicDialogRef } from "primeng/dynamicdialog";
import { Categoria } from "../../models/Categorias";
import { IDropdown } from "../../models/Dropdown";
import { MessagesService } from "../../services/messages.service";
import { NotificationService } from "../../services/notification.service";
import { finalize } from "rxjs";
import { ColumnComponent } from "../../../shared/components/column/column.component";
import { InputFormComponent } from "../../components/input-form/input-form.component";
import { DropdownModule } from "primeng/dropdown";
import { RowComponent } from "../../../shared/components/row/row.component";
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
        DropdownModule,
        RowComponent,
        ColorPickerModule,
        Button,
    ],
})
export class ModalCategoriaComponent implements OnInit {
  formAddCategoria!: FormGroup;
  tipoOptions: IDropdown[] = [
    {
      id: 1,
      text: "Receita",
    },
    {
      id: 2,
      text: "Despesa",
    },
  ];

  protected isLoading: boolean = false;

  constructor(
    private _categoriaService: CategoriasService,
    private _fb: FormBuilder,
    private _messagesService: MessagesService,
    private _notificationService: NotificationService,
    private ref: DynamicDialogRef,
    private config: DynamicDialogConfig
  ) {}

  ngOnInit(): void {
    this.formAddCategoria = this._fb.group({
      cat_id: [this.config.data.cat_id || null],
      cat_nome: [this.config.data.cat_nome || null],
      usr_id: [this.config.data.usr_id || null],
      cat_cor: [this.config.data.cat_cor || null],
      cat_tip_id: [this.config.data.cat_tip_id || null],
    });
  }

  protected inserirOuAtualizarCategoria() {
    this.isLoading = false;
    const form = this.formAddCategoria.getRawValue();

    if (form.cat_id) {
      this._atualizarCategoria(form);
      return;
    }
    this._inserirCategoria(form);
  }

  private _inserirCategoria(form: Categoria) {
    this._categoriaService
      .addCategoria$(form)
      .pipe(finalize(() => (this.isLoading = false)))
      .subscribe({
        next: () => {
          this._messagesService.showSuccess("Categoria inserida com sucesso!");
          this.ref.close();
          this._notificationService.notifyChanges({ refresh: true });
        },
      });
  }

  private _atualizarCategoria(form: Categoria) {
    this._categoriaService
      .atualizarCategoria$(form)
      .pipe(finalize(() => (this.isLoading = false)))
      .subscribe({
        next: () => {
          this._messagesService.showSuccess("Categoria atualizada com sucesso!");
          this.ref.close();
          this._notificationService.notifyChanges({ refresh: true });
        },
      });
  }
}
