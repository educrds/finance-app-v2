import { Component, OnInit } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { take } from 'rxjs';
import { ITransacao } from '../../interfaces/ITransacao';
import { NotificationService } from '../../services/notification.service';
import { ConfirmationService } from 'primeng/api';
import { ModalTransacaoComponent } from '../../templates/modal-transacao/modal-transacao.component';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { DateFilterService } from '../../services/date-filter.service';
import { ITransacoesSoma } from '../../interfaces/ITransacoesSoma';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrl: './main.component.scss',
  providers: [ConfirmationService, DialogService],
})
export class MainComponent implements OnInit {
  protected transacoes: ITransacao[] = [];
  protected somatorio!: ITransacoesSoma;

  private ref!: DynamicDialogRef;
  private queryParams: Date = new Date();

  constructor(
    private _transacoesService: TransacoesService,
    private notificacaoService: NotificationService,
    private _dateFilterService: DateFilterService,
    private confirmationService: ConfirmationService,
    private dialogService: DialogService
  ) {}

  ngOnInit(): void {
    this.atualizarTransacoes();

    this._transacoesService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.atualizarTransacoes();
      }
    });

    this._dateFilterService.notifyObservable$.subscribe((res) => {
      const { date } = res;
      if (date) {
        this.queryParams = date;
        this.atualizarTransacoes();
      }
    });
  }

  private atualizarTransacoes() {
    this._transacoesService
      .getTransacoes(this.queryParams)
      .pipe(take(1))
      .subscribe({
        next: (res) => {
          this.transacoes = res;
          this.obterTransacoesSomatorio();
        },
        error: (err) => console.log(err),
      });
  }

  private obterTransacoesSomatorio() {
    this._transacoesService
      .getTransacoesSomatorio(this.queryParams)
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.somatorio = res[0]),
        error: (err) => console.log(err),
      });
  }

  protected deletarTransacao(idTransacao: string) {
    this.confirmationService.confirm({
      message:
        'Deseja realmente excluir o registro? <br> Esta ação é irreversível.',
      header: 'Confirmação',
      icon: 'pi pi-exclamation-triangle',
      acceptIcon: 'none',
      rejectIcon: 'none',
      rejectButtonStyleClass: 'p-button-text',
      accept: () => {
        this._transacoesService.deletarTransacao(idTransacao).subscribe({
          next: () => {
            this.notificacaoService.showSuccess(
              'Registro deletado com sucesso!'
            );
            this.ngOnInit();
          },
          error: () =>
            this.notificacaoService.showError(
              'Ocorreu um erro ao deletar registro, tente novamente!'
            ),
        });
      },
    });
  }

  protected editarTransacao(transacao: ITransacao) {
    this.ref = this.dialogService.open(ModalTransacaoComponent, {
      modal: true,
      header: 'Atualizar Despesa',
      width: '35vw',
      contentStyle: { overflow: 'auto' },
      data: transacao,
    });
  }
}
