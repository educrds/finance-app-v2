import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { TransacoesService } from '../../services/transacoes.service';
import { CategoriasService } from '../../services/categorias.service';
import { IDropdown } from '../../interfaces/Dropdown';
import { DynamicDialogConfig, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ITransacao } from '../../interfaces/Transacao';
import { MessagesService } from '../../services/messages.service';
import { NotificationService } from '../../shared/services/notification.service';

@Component({
  selector: 'fin-modal-transacao',
  templateUrl: './modal-transacao.component.html',
  styleUrl: './modal-transacao.component.scss',
  providers: [],
})
export class ModalTransacaoComponent implements OnInit {
  formAddTransacao!: FormGroup;
  categoriasOptions!: IDropdown[];
  metodosOptions!: IDropdown[];

  protected loading: boolean = false;
  protected tipoTransacao!: number;

  constructor(
    private _fb: FormBuilder,
    private _notificationService: NotificationService,
    private _transacoesService: TransacoesService,
    private _messagesService: MessagesService,
    private _categoriasService: CategoriasService,
    private _ref: DynamicDialogRef,
    private _config: DynamicDialogConfig
  ) {}

  ngOnInit(): void {
    const defaultTransactionValues = {
      trs_valor: '',
      trs_data_ocorrido: new Date(),
      trs_titulo: '',
      trs_categoria: '',
      trs_usuario: '',
      trs_metodo: '',
      trs_status: false,
      trs_parcelado: false,
      data_fim_repeticao: '',
    };

    const trs_data = this._config.data.trs_data_ocorrido && new Date(this._config.data.trs_data_ocorrido);
    this.tipoTransacao = this._config.data.id_tipo_transacao;

    this.formAddTransacao = this._fb.group({
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
      data_fim_repeticao: [''],
    });

    this._transacoesService.getMetodosDropdown().subscribe({
      next: (res) => this.metodosOptions = res,
      error: () => this._messagesService.showError('Ocorreu um erro ao buscar categorias.'),
    });

    this._categoriasService
      .getCategoriasDropdown(this.tipoTransacao)
      .subscribe({
        next: (res) => this.categoriasOptions = res,
        error: () => this._messagesService.showError('Ocorreu um erro ao buscar categorias.'),
      });

    this._ref.onClose.subscribe(() => this._notificationService.notifyChanges({ closeModal: true }));
  }

  protected inserirOuAtualizarTransacao() {
    if(this.formAddTransacao.valid){
      this.loading = true;
      const form = this.formAddTransacao.getRawValue();

      if (form.trs_id) {
        this.atualizarTransacao(form);
        return;
      }
      this.inserirTransacao(form);
      return;
    }
    this.updateValidationForm(this.formAddTransacao);
  }
  
  private updateValidationForm(group: FormGroup){
    group.markAllAsTouched();
    Object.keys(group.controls).map((key: string)=>{
      const abstractControl = group.controls[key];
      abstractControl.updateValueAndValidity();
    })
  }

  private inserirTransacao(form: ITransacao) {
    this._transacoesService.addTransacao(form).subscribe({
      next: () => {
        this._messagesService.showSuccess('Transação adicionada com successo!');
        this._ref.close();
        this._notificationService.notifyChanges({ refresh: true });
      },
      error: () => this._messagesService.showError('Ocorreu um erro ao adicionar transação.'),
      complete: () => this.loading = false
    });
  }

  private atualizarTransacao(form: ITransacao) {
    this._transacoesService.atualizarTransacao(form).subscribe({
      next: () => {
        this._messagesService.showSuccess('Transação atualizada com successo!');
        this._ref.close();
        this._notificationService.notifyChanges({ refresh: true });
      },
      error: () => this._messagesService.showError('Ocorreu um erro ao atualizar transação.'),
      complete: () => this.loading = false
    });
  }
}
