import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { TransacoesService } from '../../services/transacoes.service';
import { NotificationService } from '../../services/notification.service';
import { CategoriasService } from '../../services/categorias.service';
import { IDropdown } from '../../interfaces/IDropdown';
import { DynamicDialogConfig, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ITransacao } from '../../interfaces/ITransacao';

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
    private transacoesService: TransacoesService,
    private notificationService: NotificationService,
    private categoriasService: CategoriasService,
    private ref: DynamicDialogRef,
    private config: DynamicDialogConfig
  ) {}

  ngOnInit(): void {
    if (this.config.data.trs_id) {
      this.formAddTransacao = this._fb.group({
        trs_valor: [this.config.data.trs_valor],
        trs_data_ocorrido: [new Date(this.config.data.trs_data_ocorrido)],
        trs_titulo: [this.config.data?.trs_titulo, Validators.required],
        trs_descricao: [this.config.data?.trs_descricao],
        trs_categoria: [this.config.data?.id_categoria],
        trs_usuario: [1],
        trs_tipo: [this.config.data.id_tipo_transacao],
        trs_metodo: [1],
        trs_id: [this.config.data.trs_id],
      });
    } else {
      this.formAddTransacao = this._fb.group({
        trs_valor: [''],
        trs_data_ocorrido: [new Date()],
        trs_titulo: ['', Validators.required],
        trs_descricao: [''],
        trs_categoria: [''],
        trs_usuario: [1],
        trs_tipo: [this.config.data.id_tipo_transacao],
        trs_metodo: [1],
      });
    }

    this.categoriasService.getCategorias().subscribe({
      next: (res) => (this.categoriasOptions = res),
      error: () =>
        this.notificationService.showError(
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
    this.transacoesService.addTransacao(form).subscribe({
      next: () => {
        this.notificationService.showSuccess(
          'Transação adicionada com successo!'
        );
        this.ref.close();
      },
      error: () =>
        this.notificationService.showError(
          'Ocorreu um erro ao adicionar transação.'
        ),
      complete: () => (this.loading = false),
    });
  }

  private atualizarTransacao(form: ITransacao) {
    this.transacoesService.atualizarTransacao(form).subscribe({
      next: () => {
        this.notificationService.showSuccess(
          'Transação atualizada com successo!'
        );
        this.ref.close();
      },
      error: () =>
        this.notificationService.showError(
          'Ocorreu um erro ao atualizar transação.'
        ),
      complete: () => (this.loading = false),
    });
  }
}
