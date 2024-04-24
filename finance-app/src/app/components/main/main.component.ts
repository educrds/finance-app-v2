import { Component, OnInit, ViewChild } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { ITransacoesSoma } from '../../interfaces/ITransacoesSoma';
import { TransacaoUtilService } from '../../utils/transacao-util.service';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';
import { NotificationService } from '../../shared/services/notification.service';
import { Table } from 'primeng/table';
import { ConfigCategoriaChart } from '../../interfaces/Chart';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrl: './main.component.scss',
})
export class MainComponent implements OnInit {
  @ViewChild('dt') dt: Table | undefined;

  protected transacoes: ITransacao[] = [];
  protected somatorio!: ITransacoesSoma;
  protected rowSelected!: ITransacao[] | null;

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

  private queryParams: ParamsTransacao = {
    filterDate: new Date(),
  };

  constructor(
    private _notificationService: NotificationService,
    private _transacaoUtilService: TransacaoUtilService
  ) {}

  ngOnInit(): void {
    this.fetchTransacoes(this.queryParams);

    this._notificationService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.fetchTransacoes(this.queryParams);
      }
      this.rowSelected = null;
    });

    this._notificationService.notifyObservable$.subscribe((res) => {
      const { date } = res;
      if (date) {
        this.queryParams.filterDate = date;
        this.fetchTransacoes(this.queryParams);
      }
    });
  }

  clear(table: Table) {
    table.clear();
  }

  applyFilterGlobal($event: any, stringVal: any) {
    this.dt!.filterGlobal(($event.target as HTMLInputElement).value, stringVal);
  }

  protected deletarTransacoes() {
    if (this.rowSelected) {
      const transacoesIds = this.rowSelected.map((item) => item.trs_id);
      this._transacaoUtilService.deletarTransacoesUtil(transacoesIds);
    }
  }

  protected editarTransacao(transacao: ITransacao) {
    this._transacaoUtilService.editarTransacaoUtil(transacao);
  }

  protected deletarTransacao(idTransacao: number, isParcelado: boolean) {
    this._transacaoUtilService.deletarTransacaoUtil(idTransacao, isParcelado);
  }

  protected checkStatus(transacao: ITransacao): string {
    return this._transacaoUtilService.checkStatusUtil(transacao);
  }

  private fetchTransacoes(params: ParamsTransacao) {
    this._transacaoUtilService.getTransacoesUtil(params).subscribe({
      next: (transacoes: ITransacao[]) => {
        this.transacoes = transacoes;
        this.somatorio =
          this._transacaoUtilService.obterSomatorioTransacoes(transacoes);
        this.calcularSomatorioPorCategoria(transacoes);
      },
      error: (err) => console.log(err),
    });
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
}
