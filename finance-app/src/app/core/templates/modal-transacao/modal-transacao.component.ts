import { Component, OnInit } from "@angular/core";
import { FormBuilder, FormGroup, ValidationErrors, Validators } from "@angular/forms";
import { TransacoesService } from "../../services/transacoes.service";
import { CategoriasService } from "../../services/categorias.service";
import { IDropdown } from "../../models/Dropdown";
import { DynamicDialogConfig, DynamicDialogRef } from "primeng/dynamicdialog";
import { Transacao } from "../../models/Transacao";
import { MessagesService } from "../../services/messages.service";
import { NotificationService } from "../../services/notification.service";
import { DatePickerService } from "../../services/date-picker.service";
import { Observable, finalize } from "rxjs";

@Component({
  selector: "fin-modal-transacao",
  templateUrl: "./modal-transacao.component.html",
  styleUrl: "./modal-transacao.component.scss",
  providers: [],
})
export class ModalTransacaoComponent implements OnInit {
  protected formAddTransacao!: FormGroup;

  protected categoriasOptions$!: Observable<IDropdown[]>;
  protected metodosOptions$!: Observable<IDropdown[]>;

  protected loading: boolean = false;
  protected tipoTransacao!: number;

  constructor(
    private _fb: FormBuilder,
    private _notificationService: NotificationService,
    private _transacoesService: TransacoesService,
    private _messagesService: MessagesService,
    private _categoriasService: CategoriasService,
    private _ref: DynamicDialogRef,
    private _config: DynamicDialogConfig,
    private _datePickerService: DatePickerService
  ) {}

  ngOnInit(): void {
    const defaultTransactionValues = this.getDefaultTransactionValues();

    this._initializeDatePickerListener(defaultTransactionValues);
    this._initializeForm(defaultTransactionValues);
    this._initializeDropdownOptions();

    this._ref.onClose.subscribe(() => this._notificationService.notifyChanges({ closeModal: true }));
  }

  private getDefaultTransactionValues() {
    return {
      trs_valor: "",
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

  private _initializeForm(defaultTransactionValues: any): void {
    const trs_data = this._config.data.trs_data_ocorrido && new Date(this._config.data.trs_data_ocorrido);
    this.tipoTransacao = this._config.data.id_tipo_transacao;

    this.formAddTransacao = this._fb.group(
      {
        trs_valor: [this._config.data.trs_valor || defaultTransactionValues.trs_valor, Validators.required],
        trs_data_ocorrido: [trs_data || defaultTransactionValues.trs_data_ocorrido],
        trs_titulo: [this._config.data?.trs_titulo || defaultTransactionValues.trs_titulo, Validators.required],
        trs_categoria: [this._config.data?.id_categoria || defaultTransactionValues.trs_categoria, Validators.required],
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

  private _initializeDatePickerListener(defaultTransactionValues: any) {
    this._datePickerService.datePickerObservable$.subscribe({
      next: date => (defaultTransactionValues.trs_data_ocorrido = date),
    });
  }

  private _initializeDropdownOptions(): void {
    this.metodosOptions$ = this._transacoesService.getMetodosDropdown$();
    this.categoriasOptions$ = this._categoriasService.getCategoriasDropdown$(this.tipoTransacao);
  }

  protected inserirOuAtualizarTransacao() {
    this.loading = true;

    if (this.formAddTransacao.valid) {
      const form = this.formAddTransacao.getRawValue();

      if (form.trs_id) {
        return this.atualizarTransacao(form);
      }
      return this.inserirTransacao(form);
    }
    this.loading = false;
    return this.updateValidationForm(this.formAddTransacao);
  }

  private updateValidationForm(group: FormGroup) {
    group.markAllAsTouched();
    Object.keys(group.controls).map((key: string) => {
      const abstractControl = group.controls[key];
      abstractControl.updateValueAndValidity();
    });
  }

  private inserirTransacao(form: Transacao) {
    this._transacoesService
      .addTransacao$(form)
      .pipe(finalize(() => (this.loading = false)))
      .subscribe({
        next: () => {
          this._messagesService.showSuccess("Transação adicionada com successo!");
          this._notificationService.notifyChanges({ refresh: true }, this._ref);
        },
      });
  }

  private atualizarTransacao(form: Transacao) {
    this._transacoesService
      .atualizarTransacao$(form)
      .pipe(finalize(() => (this.loading = false)))
      .subscribe({
        next: () => {
          this._messagesService.showSuccess("Transação atualizada com successo!");
          this._notificationService.notifyChanges({ refresh: true }, this._ref);
        },
      });
  }
}
