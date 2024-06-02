import { Injectable } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalTransacaoComponent } from '../../templates/modal-transacao/modal-transacao.component';
import { TransacoesSoma } from '../../interfaces/TransacoesSoma';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';
import { Observable, catchError, throwError } from 'rxjs';
import { MessagesService } from '../../services/messages.service';
import { NotificationService } from './notification.service';
import { Transacao } from '../../interfaces/Transacao';
import { ConfirmDialogComponent } from '../../templates/confirm-dialog/confirm-dialog.component';
import { ConfirmDialogService } from './confirm-dialog.service';

@Injectable({
  providedIn: 'root',
})
export class TransacaoUtilService {
  private _ref!: DynamicDialogRef;

  constructor(
    private _transacoesService: TransacoesService,
    private _notificationService: NotificationService,
    private _messagesService: MessagesService,
    private _dialogService: DialogService,
    private _confirmDialogService: ConfirmDialogService,
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

  deletarTransacaoUtil(transacao: Transacao) {
    let confirmationMessage =
      'Deseja realmente excluir o registro? Esta ação é irreversível.';
    let successMessage = 'Registro deletado com sucesso!';
    let errorMessage = 'Ocorreu um erro ao deletar registro!';

    if (transacao.trs_parcelado) {
      // lida com a lógica de excluir TODOS ou apenas UM
      this.deletarTransacoesParceladas(transacao);
    } else {
      this._messagesService.confirm(confirmationMessage, 'Confirmação', () => {
        // transformar em um metódo pq vai ser chamado em mais de um local
        this._transacoesService.deletarTransacao(transacao.trs_id).subscribe({
          next: () => {
            this._messagesService.showSuccess(successMessage);
            this._notificationService.notifyChanges({ refresh: true });
          },
          error: () => this._messagesService.showError(errorMessage),
        });
      });
    }
  }

  deletarTransacoesParceladas(transacao: Transacao) {
    const { par_id, trs_id, trs_parcelado } = transacao;

    const configModal = {
      modal: true,
      header: 'Confirmar remoção',
      width: '35vw',
      height: '15vw',
      contentStyle: { overflow: 'auto' },
    };

    const confirmationMessage = `Este registro trata-se de uma transação que se repete.<br>
    Deseja deletar <b>todos os registros</b> ou <b>apenas esse</b>?`;
    let successMessage = 'Registro deletado com sucesso!';
    let errorMessage = 'Ocorreu um erro ao deletar registro!';

    this._ref = this._dialogService.open(ConfirmDialogComponent, {
      ...configModal,
      data: {
        acceptLabel: 'Apenas selecionado',
        rejectLabel: 'Todas',
        body: confirmationMessage
      },
    });

    this._confirmDialogService.config$.subscribe((res) => {
      if (res.accept) {
        if (par_id !== null) {
          return this._transacoesService
            .deletarTransacao(par_id, !!trs_parcelado)
            .subscribe({
              next: () => {
                this._messagesService.showSuccess(successMessage);
                this._notificationService.notifyChanges({ refresh: true }, this._ref);
              },
              error: () => this._messagesService.showError(errorMessage),
            });
        }
        return this._transacoesService.deletarTransacao(trs_id).subscribe({
          next: () => {
            this._messagesService.showSuccess(successMessage);
            this._notificationService.notifyChanges({ refresh: true }, this._ref);
          },
          error: () => this._messagesService.showError(errorMessage),
        });
      } else {
        return this._transacoesService
          .deletarTodasTransacoesById(trs_id)
          .subscribe({
            next: () => {
              this._messagesService.showSuccess(successMessage);
              this._notificationService.notifyChanges({ refresh: true }, this._ref);
            },
            error: () => this._messagesService.showError(errorMessage),
          });
      }
    });
  }

  deletarTransacoesUtil(transacoesIds: number[]) {
    let confirmationMessage: string = `Deseja realmente excluir os registros? Esta ação é irreversível. <br> 
    Deseja prosseguir?`;
    let successMessage: string = 'Registros deletados com sucesso!';
    let errorMessage: string = 'Ocorreu um erro ao deletar registros!';

    this._messagesService.confirm(confirmationMessage, 'Confirmação', () => {
      transacoesIds.map((id_transacao) => {
        this._transacoesService.deletarTransacao(id_transacao).subscribe({
          next: () => {
            this._messagesService.showSuccess(successMessage);
            this._notificationService.notifyChanges({ refresh: true });
          },
          error: () => this._messagesService.showError(errorMessage),
        });
      });
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
    return this._transacoesService
      .getTransacoes(params)
      .pipe(catchError((err) => throwError(err)));
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
