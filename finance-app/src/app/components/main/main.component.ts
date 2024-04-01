import { Component, OnInit } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { take } from 'rxjs';
import { ITransacao } from '../../interfaces/ITransacao';
import { NotificationService } from '../../services/notification.service';
import { ConfirmationService } from 'primeng/api';
import { ModalTransacaoComponent } from '../modal-transacao/modal-transacao.component';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrl: './main.component.scss',
  providers: [ConfirmationService, DialogService],
})
export class MainComponent implements OnInit {
  protected transacoes: ITransacao[] = [];
  private ref!: DynamicDialogRef;

  constructor(
    private _transacoesService: TransacoesService,
    private notificacaoService: NotificationService,
    private confirmationService: ConfirmationService,
    private dialogService: DialogService,
  ) {}

  ngOnInit(): void {
    this._transacoesService
      .getTransacoes()
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.transacoes = res),
        error: (err) => console.log(err),
      });
  }

  protected deletarTransacao(idTransacao: string) {
    this.confirmationService.confirm({
      message: 'Deseja realmente excluir o registro? <br> Esta ação é irreversível.',
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
      data: transacao
    });
  }
}
