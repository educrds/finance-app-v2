import { Component, OnInit, Signal, WritableSignal, computed, signal } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { ITransacoesSoma } from '../../interfaces/ITransacoesSoma';
import { ConfigCategoriaChart } from '../../interfaces/Chart';
import { BaseTransacaoDirective } from '../../shared/directives/base-transacao.directive';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrl: './main.component.scss',
})
export class MainComponent extends BaseTransacaoDirective implements OnInit {
  protected somatorio: WritableSignal<ITransacoesSoma> = signal({
    soma_receitas: 0,
    soma_despesas: 0,
  });
  protected saldo: Signal<number> = computed(() => this.somatorio().soma_receitas - this.somatorio().soma_despesas )

  // charts
  protected entradasPorCategoria!: ConfigCategoriaChart;
  protected saidasPorCategoria!: ConfigCategoriaChart;

  protected options = {
    responsive: true,
    maintainAspectRatio: false,
    borderWidth: 0,
    plugins: {
      legend: {
        position: 'right',
        labels: {
          padding: 15,
          usePointStyle: true,
          boxHeight: 10,
          pointStyle: 'circle',
        },
      },
    },
  };

  override afterFetchTransacoes(transacoes: ITransacao[]): void {
    this.somatorio.set(
      this._transacaoUtilService.obterSomatorioTransacoes(transacoes)
    );
    this.calcularSomatorioPorCategoria(transacoes);
  }

  private calcularSomatorioPorCategoria(transacoes: ITransacao[] | any[]) {
    const resultado = transacoes.reduce(
      (acc, transacao) => {
        const { categoria_cor, categoria_nome, trs_valor, id_tipo_transacao } = transacao;
        const tipoTransacao = id_tipo_transacao === 1 ? 'entrada' : 'saida';

        const categoriaNome = categoria_nome;
        const categoriaCor = categoria_cor;
        const valor = trs_valor;

        // Cria o objeto de categoria se ainda não existir
        if (!acc[tipoTransacao][categoriaNome]) {
          acc[tipoTransacao][categoriaNome] = {
            name: categoriaNome,
            value: 0,
            cor: categoriaCor,
          };
        }

        // Soma o valor à categoria correspondente
        acc[tipoTransacao][categoriaNome].value += valor;

        return acc;
      },
      { entrada: {}, saida: {} }
    );

    this.entradasPorCategoria = this.configPieCharts(resultado.entrada);
    this.saidasPorCategoria = this.configPieCharts(resultado.saida);
  }

  private configPieCharts(categoriasPorTipo: ConfigCategoriaChart) {
    const objCategorias = Object.values(categoriasPorTipo);

    let resultadoPorCategoria = {
      labels: objCategorias.map((item: any) => item.name),
      datasets: [
        {
          data: objCategorias.map((item: any) => item.value),
          backgroundColor: objCategorias.map((item: any) => item.cor),
        },
      ],
    };

    return resultadoPorCategoria;
  }

  protected sumSelected(transactions: any): number {
    return transactions.reduce(
      (acc: number, transacao: ITransacao) => acc + transacao.trs_valor,
      0
    );
  }
}
