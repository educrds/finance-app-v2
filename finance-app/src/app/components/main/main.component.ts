import { Component, OnInit, Signal, WritableSignal, computed, signal } from '@angular/core';
import { Transacao } from '../../interfaces/Transacao';
import { TransacoesSoma } from '../../interfaces/TransacoesSoma';
import { BaseTransacaoDirective } from '../../shared/directives/base-transacao.directive';
import Util from '../../shared/utils';
import { CategoriaChart } from '../../interfaces/Chart';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrls: ['./main.component.scss'],
})
export class MainComponent extends BaseTransacaoDirective implements OnInit {
  protected somatorio: WritableSignal<TransacoesSoma> = signal({
    soma_receitas: 0,
    soma_despesas: 0,
  });
  protected saldo: Signal<number> = computed(
    () => this.somatorio().soma_receitas - this.somatorio().soma_despesas
  );

  // charts
  protected entradasPorCategoria!: CategoriaChart;
  protected saidasPorCategoria!: CategoriaChart;

  protected override afterFetchTransacoes(transacoes: Transacao[]): void {
    this.updateSomatorio(transacoes);
    this.updateCharts(transacoes);
  }

  // Atualizando a soma das transações.
  private updateSomatorio(transacoes: Transacao[]): void {
    this.somatorio.set(
      this._transacaoUtilService.obterSomatorioTransacoes(transacoes)
    );
  }

  // Atualizando os dados dos gráficos
  private updateCharts(transacoes: Transacao[]): void {
    const { entrada, saida } = Util.calcularSomatorioPorCategoria(transacoes);
    this.entradasPorCategoria = entrada;
    this.saidasPorCategoria = saida;
  }

  protected sumSelected(transactions: Transacao[]): number {
    return transactions.reduce(
      (acc: number, transacao: Transacao) => acc + transacao.trs_valor,
      0
    );
  }
}
