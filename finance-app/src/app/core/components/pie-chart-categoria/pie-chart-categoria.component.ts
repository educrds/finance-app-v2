import {
  Component,
  Input,
  OnChanges,
  OnInit,
  SimpleChanges,
} from '@angular/core';
import {
  CategoriaChartItem,
  ChartOptions,
} from '../../models/Chart';

import SharedUtil from '../../../shared/utils';

@Component({
  selector: 'fin-pie-chart-categoria',
  templateUrl: './pie-chart-categoria.component.html',
  styleUrls: ['./pie-chart-categoria.component.scss'],
})
export class PieChartCategoriaComponent implements OnInit, OnChanges {
  @Input() chartData!: CategoriaChartItem;
  protected chartOptions!: Partial<ChartOptions> | any;

  ngOnInit(): void {
    if (this.chartData) {
      this.configPieCharts();
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    const isEqual = SharedUtil.objectCompare(changes['chartData'].currentValue, changes['chartData'].previousValue)

    if (changes['chartData'] && isEqual) {
      this.chartOptions = undefined;
      this.configPieCharts();
    }
  }

  // Configurando gráfico de pizza com dados já modelados
  private configPieCharts() {
    const categoryItems: CategoriaChartItem[] = Object.values(this.chartData);

    const colors = categoryItems.map((item: CategoriaChartItem) => item.cor);
    const series = categoryItems.map((item: CategoriaChartItem) => item.value);

    this.chartOptions = {
      series: series,
      chart: {
        type: 'pie',
        height: 255
      },
      options: {
        stroke: {
          show: false,
        },
        legend: {
          fontSize: '14px',
          horizontalAlign: 'right',
          position: 'right',
          labels: {
            colors: '#dedede',
          },
        },
        dataLabels: {
          enabled: false,
        },
        tooltip: {
          y: {
            formatter: (val: any) => {
              return SharedUtil.numToCurrency(val);
            },
          },
        },
      },
      labels: categoryItems.map((item: CategoriaChartItem) => item.name),
      colors: colors,
      responsive: [
        {
          breakpoint: 480,
          options: {
            chart: {
              width: 200,
            },
            legend: {
              position: 'bottom',
            },
          },
        },
      ],
    };
  }
}
