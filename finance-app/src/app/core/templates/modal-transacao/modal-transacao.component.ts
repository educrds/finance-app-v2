import { Component, OnInit, inject } from "@angular/core";
import { FormBuilder, FormGroup, ValidationErrors, Validators, FormsModule, ReactiveFormsModule } from "@angular/forms";
import { TransacoesService } from "../../services/transacoes.service";
import { CategoriasService } from "../../services/categorias.service";
import { IDropdown } from "../../models/Dropdown";
import { DynamicDialogConfig, DynamicDialogRef } from "primeng/dynamicdialog";
import { Transacao, TransacaoForm } from "../../models/Transacao";
import { MessagesService } from "../../services/messages.service";
import { NotificationService } from "../../services/notification.service";
import { DatePickerService } from "../../services/date-picker.service";
import { Observable, finalize } from "rxjs";
import { ColumnComponent } from "../../../shared/components/column/column.component";
import { InputFormComponent } from "../../components/input-form/input-form.component";
import { RowComponent } from "../../../shared/components/row/row.component";
import { ToggleSwitch } from 'primeng/toggleswitch';
import { Select } from 'primeng/select';
import { DatePicker } from "primeng/datepicker";
import { Button } from "primeng/button";
import { AsyncPipe } from "@angular/common";

@Component({
    selector: "fin-modal-transacao",
    templateUrl: "./modal-transacao.component.html",
    styleUrl: "./modal-transacao.component.scss",
    standalone: true,
    imports: [
        FormsModule,
        ReactiveFormsModule,
        ColumnComponent,
        InputFormComponent,
        RowComponent,
        ToggleSwitch,
        Select,
        DatePicker,
        Button,
        AsyncPipe,
    ],
})
export class ModalTransacaoComponent implements OnInit {
  protected formAddTransacao!: FormGroup;

  protected categoriasOptions$!: Observable<IDropdown[]>;
  protected metodosOptions$!: Observable<IDropdown[]>;

  protected isLoading: boolean = false;
  protected tipoTransacao!: number;

  private _fb = inject(FormBuilder);
  private _notificationService = inject(NotificationService);
  private _transacoesService = inject(TransacoesService);
  private _messagesService = inject(MessagesService);
  private _categoriasService = inject(CategoriasService);
  private _ref = inject(DynamicDialogRef);
  private _config = inject(DynamicDialogConfig);
  private _datePickerService = inject(DatePickerService);

  ngOnInit(): void {
    const defaultTransactionValues = this.getDefaultTransactionValues();

    this._initializeDatePickerListener(defaultTransactionValues);
    this._initializeForm(defaultTransactionValues);
    this._initializeDropdownOptions();

    this._ref.onClose.subscribe(() => this._notificationService.notifyChanges({ closeModal: true }));
  }

  private getDefaultTransactionValues(): TransacaoForm {
    return {
      trs_valor: 0,
      trs_data_ocorrido: new Date(),
      trs_titulo: "",
      trs_categoria: "",
      trs_usuario: "",
      trs_metodo: "",
      trs_status: false,
      trs_parcelado: false,
      data_fim_repeticao: "",
    };
  }

  private _initializeForm(defaultTransactionValues: TransacaoForm): void {
    const trs_data = this._config.data.trs_data_ocorrido && new Date(this._config.data.trs_data_ocorrido);
    this.tipoTransacao = this._config.data.id_tipo_transacao;

    this.formAddTransacao = this._fb.group(
      {
        trs_valor: [this._config.data.trs_valor || defaultTransactionValues.trs_valor, Validators.required],
        trs_data_ocorrido: [trs_data || defaultTransactionValues.trs_data_ocorrido],
        trs_titulo: [this._config.data.trs_titulo || defaultTransactionValues.trs_titulo, Validators.required],
        trs_categoria: [
          this._config.data?.id_categoria || defaultTransactionValues.trs_categoria,
          Validators.required,
        ],
        trs_usuario: [defaultTransactionValues.trs_usuario],
        trs_tipo: [this.tipoTransacao],
        trs_metodo: [this._config.data.metodo_id || defaultTransactionValues.trs_metodo, Validators.required],
        trs_status: [!!this._config.data.trs_status || defaultTransactionValues.trs_status],
        trs_id: [this._config.data.trs_id || null],
        trs_parcelado: [this._config.data.trs_parcelado || defaultTransactionValues.trs_parcelado],
        data_fim_repeticao: [""],
      },
      { validators: [this._verifyDates()] }
    );
  }

  private _verifyDates(): Validators {
    return (form: FormGroup): ValidationErrors | null => {
      const startDate: Date = form.get("trs_data_ocorrido")?.value;
      const endDate: Date = form.get("data_fim_repeticao")?.value;

      if (startDate && endDate) {
        const isRangeValid = endDate.getTime() - startDate.getTime() > 0;
        return isRangeValid ? null : { invalidDates: true };
      }

      return null;
    };
  }

  private _initializeDatePickerListener(defaultTransactionValues: TransacaoForm) {
    this._datePickerService.datePickerObservable$.subscribe({
      next: date => (defaultTransactionValues.trs_data_ocorrido = date),
    });
  }

  private _initializeDropdownOptions(): void {
    this.metodosOptions$ = this._transacoesService.getMetodosDropdown$();
    this.categoriasOptions$ = this._categoriasService.getCategoriasDropdown$(this.tipoTransacao);
  }

  protected inserirOuAtualizarTransacao(closeModal: boolean = true) {
    this.isLoading = true;

    if (this.formAddTransacao.valid) {
      const form = this.formAddTransacao.getRawValue();

      if (form.trs_id) {
        return this.atualizarTransacao(form);
      } 
      return this.inserirTransacao(form, closeModal);
    }
    this.isLoading = false;
    return this.updateValidationForm(this.formAddTransacao);
  }

  private updateValidationForm(group: FormGroup) {
    group.markAllAsTouched();
    Object.keys(group.controls).map((key: string) => {
      const abstractControl = group.controls[key];
      abstractControl.updateValueAndValidity();
    });
  }

  private inserirTransacao(form: Transacao, closeModal: boolean) {
    this._transacoesService
      .addTransacao$(form)
      .pipe(finalize(() => (this.isLoading = false)))
      .subscribe({
        next: () => {
          this._messagesService.showSuccess("Transação adicionada com successo!");
          this._notificationService.notifyChanges({ refresh: true }, this._ref, closeModal);
          !closeModal && this._initializeForm(this.getDefaultTransactionValues());
        },
      });
  }

  private atualizarTransacao(form: Transacao) {
    this._transacoesService
      .atualizarTransacao$(form)
      .pipe(finalize(() => (this.isLoading = false)))
      .subscribe({
        next: () => {
          this._messagesService.showSuccess("Transação atualizada com successo!");
          this._notificationService.notifyChanges({ refresh: true }, this._ref);
        },
      });
  }
}
