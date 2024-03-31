import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { TransacoesService } from '../../services/transacoes.service';
import { NotificationService } from '../../services/notification.service';
import { CategoriasService } from '../../services/categorias.service';
import { IDropdown } from '../../interfaces/IDropdown';
import { DialogService, DynamicDialogConfig, DynamicDialogRef } from 'primeng/dynamicdialog';

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
    this.formAddTransacao = this._fb.group({
      trs_valor: [''],
      trs_data_ocorrido: [new Date()],
      trs_titulo: ['', Validators.required],
      trs_descricao: [''],
      trs_categoria: [''],
      trs_usuario: [1],
      trs_tipo: [this.config.data.trs_tipo],
      trs_metodo: [1],
    });

    this.categoriasService.getCategorias().subscribe({
      next: (res) => (this.categoriasOptions = res),
      error: () =>
        this.notificationService.showError(
          'Ocorreu um erro ao buscar categorias.'
        ),
    });
  }

  protected adicionarNovaTransacao() {
    this.loading = true;

    const form = this.formAddTransacao.getRawValue();

    this.transacoesService.addTransacao(form).subscribe({
      next: () => {
        this.notificationService.showSuccess(
          'Transação adicionada com successo!'
        );
        this.ref.close();
        // fechar modal aqui
      },
      error: () =>
        this.notificationService.showError(
          'Ocorreu um erro ao adicionar transação.'
        ),
      complete: () => (this.loading = false),
    });
  }
}
