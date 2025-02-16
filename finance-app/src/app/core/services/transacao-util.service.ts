import { Injectable, inject } from "@angular/core";
import { DialogService, DynamicDialogRef } from "primeng/dynamicdialog";
import { ModalTransacaoComponent } from "../templates/modal-transacao/modal-transacao.component";
import { TransacoesSoma, TransacoesSomaKey } from "../models/TransacoesSoma";
import { MessagesService } from "./messages.service";
import { NotificationService } from "./notification.service";
import { Transacao } from "../models/Transacao";
import { ConfirmDialogService } from "../../shared/services/confirm-dialog.service";
import { TransacoesService } from "./transacoes.service";
import { ConfirmDialogComponent } from "../../shared/components/confirm-dialog/confirm-dialog.component";

const TRANSACTION_TYPE_MAP: { [key: number]: TransacoesSomaKey } = {
  1: "soma_receitas",
  2: "soma_despesas",
};
@Injectable({
  providedIn: "root",
})
export class TransacaoUtilService {
  #_ref!: DynamicDialogRef;

  #_transacoesService = inject(TransacoesService);
  #_notificationService = inject(NotificationService);
  #_messagesService = inject(MessagesService);
  #_dialogService = inject(DialogService);
  #_confirmDialogService = inject(ConfirmDialogService);

  public obterSomatorioTransacoes(transacoes: Transacao[]): TransacoesSoma {
    return transacoes.reduce(
      (acc: TransacoesSoma, transacao: Transacao) => {
        const { id_tipo_transacao, trs_valor } = transacao;
        const transactionTypeKey: TransacoesSomaKey = TRANSACTION_TYPE_MAP[id_tipo_transacao];

        acc[transactionTypeKey] += trs_valor;
        return acc;
      },
      { soma_receitas: 0, soma_despesas: 0 }
    );
  }

  public deletarTransacaoUtil(transacao: Transacao) {
    const confirmationMessage = "Deseja realmente excluir o registro? Esta ação é irreversível.";
    const successMessage = "Registro deletado com sucesso!";
    const errorMessage = "Ocorreu um erro ao deletar registro!";

    if (transacao.trs_parcelado) {
      // lida com a lógica de excluir TODOS ou apenas UM
      this.deletarTransacoesParceladas(transacao);
    } else {
      this.#_messagesService.confirm(confirmationMessage, "Confirmação", () => {
        // transformar em um metódo pq vai ser chamado em mais de um local
        this.#_transacoesService.deletarTransacao$(transacao.trs_id).subscribe({
          next: () => {
            this.#_messagesService.showSuccess(successMessage);
            this.#_notificationService.notifyChanges({ refresh: true });
          },
          error: () => this.#_messagesService.showError(errorMessage),
        });
      });
    }
  }

  public deletarTransacoesParceladas(transacao: Transacao) {
    const { par_id, trs_id, trs_parcelado } = transacao;

    const configModal = {
      modal: true,
      header: "Confirmar remoção",
      closable: true
    };

    const confirmationMessage = `Este registro trata-se de uma transação que se repete.<br>
    Deseja deletar <b>todos os registros</b> ou <b>apenas esse</b>?`;
    const successMessage = "Registro deletado com sucesso!";
    const errorMessage = "Ocorreu um erro ao deletar registro!";

    this.#_ref = this.#_dialogService.open(ConfirmDialogComponent, {
      ...configModal,
      data: {
        acceptLabel: "Apenas selecionado",
        rejectLabel: "Todas",
        body: confirmationMessage,
      },
    });

    this.#_confirmDialogService.config$.subscribe(res => {
      if (res['accept']) {
        if (par_id !== null) {
          return this.#_transacoesService.deletarTransacao$(par_id, !!trs_parcelado).subscribe({
            next: () => {
              this.#_messagesService.showSuccess(successMessage);
              this.#_notificationService.notifyChanges({ refresh: true }, this.#_ref);
            },
            error: () => this.#_messagesService.showError(errorMessage),
          });
        }
        return this.#_transacoesService.deletarTransacao$(trs_id).subscribe({
          next: () => {
            this.#_messagesService.showSuccess(successMessage);
            this.#_notificationService.notifyChanges({ refresh: true }, this.#_ref);
          },
          error: () => this.#_messagesService.showError(errorMessage),
        });
      } else {
        return this.#_transacoesService.deletarTodasTransacoesById$(trs_id).subscribe({
          next: () => {
            this.#_messagesService.showSuccess(successMessage);
            this.#_notificationService.notifyChanges({ refresh: true }, this.#_ref);
          },
          error: () => this.#_messagesService.showError(errorMessage),
        });
      }
    });
  }

  public deletarTransacoesUtil(transacoesIds: number[]) {
    const confirmationMessage: string = `Deseja realmente excluir os registros? Esta ação é irreversível. <br> 
    Deseja prosseguir?`;
    const successMessage: string = "Registros deletados com sucesso!";
    const errorMessage: string = "Ocorreu um erro ao deletar registros!";

    this.#_messagesService.confirm(confirmationMessage, "Confirmação", () => {
      transacoesIds.map(id_transacao => {
        this.#_transacoesService.deletarTransacao$(id_transacao).subscribe({
          next: () => {
            this.#_messagesService.showSuccess(successMessage);
            this.#_notificationService.notifyChanges({ refresh: true });
          },
          error: () => this.#_messagesService.showError(errorMessage),
        });
      });
    });
  }

  public editarTransacaoUtil(transacao: Transacao) {
    const tipoTransacao = transacao.id_tipo_transacao === 1 ? "Receita" : "Despesa";

    this.#_ref = this.#_dialogService.open(ModalTransacaoComponent, {
      modal: true,
      header: `Atualizar ${tipoTransacao}`,
      closable: true,
      contentStyle: { overflow: "auto" },
      data: transacao,
    });
  }
}
