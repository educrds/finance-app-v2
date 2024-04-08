import { Injectable } from '@angular/core';
import { ITransacao } from '../interfaces/ITransacao';
import { TransacoesService } from '../services/transacoes.service';
import { NotificationService } from '../services/notification.service';
import { ConfirmationService } from 'primeng/api';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalTransacaoComponent } from '../templates/modal-transacao/modal-transacao.component';
import { ITransacoesSoma } from '../interfaces/ITransacoesSoma';
import { ParamsTransacao } from '../interfaces/ParamsTransacao';
import { Observable, catchError, take, throwError } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class TransacaoUtilService {
  private _ref!: DynamicDialogRef;

  constructor(
    private _transacoesService: TransacoesService,
    private _notificacaoService: NotificationService,
    private _confirmationService: ConfirmationService,
    private _dialogService: DialogService
  ) {}

  obterSomatorioTransacoes(transacoes: ITransacao[]): ITransacoesSoma {
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
    let confirmationMessage =
      'Deseja realmente excluir o registro? <br> Esta ação é irreversível.';
    let successMessage = 'Registro deletado com sucesso!';
    let errorMessage = 'Ocorreu um erro ao deletar registro!';

    if (isParcelado) {
      confirmationMessage = `Este registro trata-se de uma transação que se repete. <br> 
      Esta ação deletará também as transações relativas as mese(s) posterior(es). <br>
      Deseja prosseguir?`;
      successMessage = 'Registros deletados com sucesso!';
      errorMessage = 'Ocorreu um erro ao deletar registros!';
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
            this._notificacaoService.showSuccess(successMessage);
            this._transacoesService.notifyChanges({ refresh: true });
          },
          error: () => this._notificacaoService.showError(errorMessage),
        });
      },
    });
  }

  editarTransacaoUtil(transacao: ITransacao) {
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

  getTransacoesUtil(params: ParamsTransacao): Observable<ITransacao[]> {
    return this._transacoesService.getTransacoes(params).pipe(
      catchError((err) => {
        console.log(err);
        return throwError(err); // Trata o erro e propaga-o
      })
    );
  }

  checkStatusUtil(transacao: ITransacao): string {
    let status = '';

    if (transacao.id_tipo_transacao === 1) {
      if (transacao.trs_status) {
        status = 'Recebida';
      } else {
        status = 'A Receber';
      }
    }

    if (transacao.id_tipo_transacao === 2) {
      if (transacao.trs_status) {
        status = 'Paga';
      } else {
        status = 'A Pagar';
      }
    }

    return status;
  }
}
