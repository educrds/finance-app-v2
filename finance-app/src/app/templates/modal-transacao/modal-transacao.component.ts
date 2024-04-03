import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { TransacoesService } from '../../services/transacoes.service';
import { NotificationService } from '../../services/notification.service';
import { CategoriasService } from '../../services/categorias.service';
import { IDropdown } from '../../interfaces/IDropdown';
import { DynamicDialogConfig, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ITransacao } from '../../interfaces/ITransacao';
import { Router } from '@angular/router';

@Component({
  selector: 'fin-modal-transacao',
  templateUrl: './modal-transacao.component.html',
  styleUrl: './modal-transacao.component.scss',
  providers: [],
})
export class ModalTransacaoComponent implements OnInit {
  formAddTransacao!: FormGroup;
  categoriasOptions!: IDropdown[];
  
  protected loading: boolean = false;

  constructor(
    private _fb: FormBuilder,
    private _transacoesService: TransacoesService,
    private _notificationService: NotificationService,
    private _categoriasService: CategoriasService,
    private _ref: DynamicDialogRef,
    private _config: DynamicDialogConfig,
  ) {}

  ngOnInit(): void {
    if (this._config.data.trs_id) {
      this.formAddTransacao = this._fb.group({
        trs_valor: [this._config.data.trs_valor],
        trs_data_ocorrido: [new Date(this._config.data.trs_data_ocorrido)],
        trs_titulo: [this._config.data?.trs_titulo, Validators.required],
        trs_descricao: [this._config.data?.trs_descricao],
        trs_categoria: [this._config.data?.id_categoria],
        trs_usuario: [1],
        trs_tipo: [this._config.data.id_tipo_transacao],
        trs_metodo: [1],
        trs_status: [!!this._config.data.trs_status],
        trs_id: [this._config.data.trs_id],
      });
    } else {
      this.formAddTransacao = this._fb.group({
        trs_valor: [''],
        trs_data_ocorrido: [new Date()],
        trs_titulo: ['', Validators.required],
        trs_descricao: [''],
        trs_categoria: [''],
        trs_usuario: [1],
        trs_tipo: [this._config.data.id_tipo_transacao],
        trs_metodo: [1],
        trs_status: [false],
      });
    }

    this._categoriasService.getCategoriasDropdown().subscribe({
      next: (res) => (this.categoriasOptions = res),
      error: () =>
        this._notificationService.showError(
          'Ocorreu um erro ao buscar categorias.'
        ),
    });
  }

  protected inserirOuAtualizarTransacao() {
    this.loading = true;
    const form = this.formAddTransacao.getRawValue();

    if (form.trs_id) {
      this.atualizarTransacao(form);
      return;
    }
    this.inserirTransacao(form);
  }

  private inserirTransacao(form: ITransacao) {
    this._transacoesService.addTransacao(form).subscribe({
      next: () => {
        this._notificationService.showSuccess(
          'Transação adicionada com successo!'
        );
        this._ref.close();
      },
      error: () =>
        this._notificationService.showError(
          'Ocorreu um erro ao adicionar transação.'
        ),
      complete: () => (this.loading = false),
    });
  }

  private atualizarTransacao(form: ITransacao) {
    this._transacoesService.atualizarTransacao(form).subscribe({
      next: () => {
        this._notificationService.showSuccess(
          'Transação atualizada com successo!'
        );
        this._ref.close();
      },
      error: () =>
        this._notificationService.showError(
          'Ocorreu um erro ao atualizar transação.'
        ),
      complete: () => (this.loading = false),
    });
  }
}
