import { Component, ElementRef, Input, ViewChild, inject } from '@angular/core';
import { Transacao } from '../../../core/interfaces/Transacao';
import { Table } from 'primeng/table';
import { TransacaoUtilService } from '../../services/transacao-util.service';

@Component({
  selector: 'fin-transacao-table',
  templateUrl: './transacao-table.component.html',
  styleUrl: './transacao-table.component.scss',
})
export class TransacaoTableComponent {
  @ViewChild('dt') dt: Table | undefined;
  @ViewChild('inputSearch') inputSearch: ElementRef | undefined;
  
  @Input() transacoes: Transacao[] = [];
  @Input() rowSelected: Transacao[] = [];

  private _transacaoUtilService = inject(TransacaoUtilService);

  protected clear(table: Table): void {
    if(this.inputSearch){
      this.inputSearch.nativeElement.value = null;
    }
    table.clear();
  }

  protected applyFilterGlobal($event: any, stringVal: any): void {
    this.dt!.filterGlobal(($event.target as HTMLInputElement).value, stringVal);
  }

  protected updateSelectionRows(newSelection: Transacao[]): void{
    this.rowSelected = newSelection;
  }

  // configurando gráfico de pizza com dados já modelados
  protected sumSelected(transactions: any): number {
    return transactions.reduce(
      (acc: number, transacao: Transacao) => acc + transacao.trs_valor,
      0
    );
  }

  protected editarTransacao(transacao: Transacao): void {
    this._transacaoUtilService.editarTransacaoUtil(transacao);
  }

  protected deletarTransacao(transacao: Transacao): void {
    this._transacaoUtilService.deletarTransacaoUtil(transacao);
  }

  protected deletarTransacoes(): void {
    if (this.rowSelected) {
      const transacoesIds = this.rowSelected.map((item) => item.trs_id);
      this._transacaoUtilService.deletarTransacoesUtil(transacoesIds);
    }
  }

  protected checkStatus(transacao: Transacao): string {
    return this._transacaoUtilService.checkStatusUtil(transacao);
  }

}
