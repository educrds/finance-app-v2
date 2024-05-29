import { Component, Input, OnInit } from '@angular/core';
import { CategoriaChart, CategoriaChartItem, ConfigCategoriaChart } from '../../../../interfaces/Chart';

@Component({
  selector: 'fin-pie-chart-categoria',
  templateUrl: './pie-chart-categoria.component.html',
  styleUrl: './pie-chart-categoria.component.scss',
})
export class PieChartCategoriaComponent implements OnInit {
  @Input() chartData!: CategoriaChart;

  protected formattedChartData!: ConfigCategoriaChart;
  // charts options
  protected chartOptions = {
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

  ngOnInit(): void {
    this.formattedChartData = this.configPieCharts(this.chartData);
  }

  // configurando gráfico de pizza com dados já modelados
  private configPieCharts(categoriasPorTipo: CategoriaChart): ConfigCategoriaChart {
    const categoryItems: CategoriaChartItem[] = Object.values(categoriasPorTipo);

    const formattedData = {
      labels: categoryItems.map((item: CategoriaChartItem) => item.name),
      datasets: [
        {
          data: categoryItems.map((item: CategoriaChartItem) => item.value),
          backgroundColor: categoryItems.map((item: CategoriaChartItem) => item.cor),
        },
      ],
    };

    return formattedData ;
  }
}