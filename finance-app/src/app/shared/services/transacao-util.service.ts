import { Injectable } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { ConfirmationService } from 'primeng/api';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalTransacaoComponent } from '../../templates/modal-transacao/modal-transacao.component';
import { TransacoesSoma } from '../../interfaces/TransacoesSoma';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';
import { Observable, catchError, throwError } from 'rxjs';
import { MessagesService } from '../../services/messages.service';
import { NotificationService } from './notification.service';
import { Transacao } from '../../interfaces/Transacao';

@Injectable({
  providedIn: 'root',
})
export class TransacaoUtilService {
  private _ref!: DynamicDialogRef;

  constructor(
    private _transacoesService: TransacoesService,
    private _notificationService: NotificationService,
    private _messagesService: MessagesService,
    private _confirmationService: ConfirmationService,
    private _dialogService: DialogService
  ) {}

  obterSomatorioTransacoes(transacoes: Transacao[]): TransacoesSoma {
    return transacoes.reduce(
      (acc, transacao) => {
        if (transacao.id_tipo_transacao === 1) {
          acc.soma_receitas += transacao.trs_valor;
        } else {
          acc.soma_despesas += transacao.trs_valor;
        }

        return acc;
      },
      { soma_receitas: 0, soma_despesas: 0 }
    );
  }

  deletarTransacaoUtil(idTransacao: number, isParcelado: boolean) {
    let confirmationMessage: string;
    let successMessage: string;
    let errorMessage: string;

    if (isParcelado) {
      confirmationMessage = `Este registro trata-se de uma transação que se repete. <br>
        Esta ação deletará também as transações relativas as mese(s) posterior(es). 
        Deseja prosseguir?`;
      successMessage = 'Registros deletados com sucesso!';
      errorMessage = 'Ocorreu um erro ao deletar registros!';
    } else {
      confirmationMessage =
        'Deseja realmente excluir o registro? Esta ação é irreversível.';
      successMessage = 'Registro deletado com sucesso!';
      errorMessage = 'Ocorreu um erro ao deletar registro!';
    }

    this._confirmationService.confirm({
      message: confirmationMessage,
      header: 'Confirmação',
      icon: 'pi pi-exclamation-triangle',
      acceptIcon: 'none',
      rejectIcon: 'none',
      rejectButtonStyleClass: 'p-button-text',
      accept: () => {
        this._transacoesService.deletarTransacao(idTransacao).subscribe({
          next: () => {
            this._messagesService.showSuccess(successMessage);
            this._notificationService.notifyChanges({ refresh: true });
          },
          error: () => this._messagesService.showError(errorMessage),
        });
      },
    });
  }

  deletarTransacoesUtil(transacoesIds: number[]) {
    let confirmationMessage: string = `Deseja realmente excluir os registros? Esta ação é irreversível. <br> 
    Deseja prosseguir?`;
    let successMessage: string = 'Registros deletados com sucesso!';
    let errorMessage: string = 'Ocorreu um erro ao deletar registros!';

    this._confirmationService.confirm({
      message: confirmationMessage,
      header: 'Confirmação',
      icon: 'pi pi-exclamation-triangle',
      acceptIcon: 'none',
      rejectIcon: 'none',
      rejectButtonStyleClass: 'p-button-text',
      accept: () => {
        transacoesIds.map((idTransacao) => {
          this._transacoesService.deletarTransacao(idTransacao).subscribe({
            next: () => {
              this._messagesService.showSuccess(successMessage);
              this._notificationService.notifyChanges({ refresh: true });
            },
            error: () => this._messagesService.showError(errorMessage),
          });
        });
      },
    });
  }

  editarTransacaoUtil(transacao: Transacao) {
    const tipoTransacao =
      transacao.id_tipo_transacao === 1 ? 'Receita' : 'Despesa';

    this._ref = this._dialogService.open(ModalTransacaoComponent, {
      modal: true,
      header: `Atualizar ${tipoTransacao}`,
      width: '35vw',
      contentStyle: { overflow: 'auto' },
      data: transacao,
    });
  }

  getTransacoesUtil(params: ParamsTransacao): Observable<Transacao[]> {
    return this._transacoesService.getTransacoes(params).pipe(
      catchError((err) => throwError(err))
    );
  }

  checkStatusUtil(transacao: Transacao): string {
    let status = '';

    if (transacao.id_tipo_transacao === 1) {
      status = transacao.trs_status ? 'Recebida' : 'A Receber';
    } else if (transacao.id_tipo_transacao === 2) {
      status = transacao.trs_status ? 'Paga' : 'A Pagar';
    }

    return status;
  }
}
