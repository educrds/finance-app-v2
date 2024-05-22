import { Component, OnInit } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { ITransacoesSoma } from '../../interfaces/ITransacoesSoma';
import { ConfigCategoriaChart } from '../../interfaces/Chart';
import { BaseTransacaoComponent } from '../../shared/components/base-transacao/base-transacao.component';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrl: './main.component.scss',
})
export class MainComponent extends BaseTransacaoComponent implements OnInit {
  protected somatorio!: ITransacoesSoma;
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
    this.somatorio = this._transacaoUtilService.obterSomatorioTransacoes(transacoes);
    this.calcularSomatorioPorCategoria(transacoes);
  }

  private calcularSomatorioPorCategoria(transacoes: ITransacao[] | any[]) {
    const resultado = transacoes.reduce(
      (acc, transacao) => {
        const tipoTransacao =
          transacao.id_tipo_transacao === 1 ? 'entrada' : 'saida';
        const categoria = transacao.categoria_nome;
        const categoriaCor = transacao.categoria_cor;
        const valor = transacao.trs_valor;

        // Cria o objeto de categoria se ainda não existir
        if (!acc[tipoTransacao][categoria]) {
          acc[tipoTransacao][categoria] = {
            name: categoria,
            value: 0,
            cor: categoriaCor,
          };
        }

        // Soma o valor à categoria correspondente
        acc[tipoTransacao][categoria].value += valor;

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
    return transactions.reduce((acc:number, transacao:ITransacao) => acc + transacao.trs_valor, 0)
  }
}
