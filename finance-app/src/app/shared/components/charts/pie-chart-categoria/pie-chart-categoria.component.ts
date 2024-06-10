import {
  Component,
  Input,
  OnChanges,
  OnInit,
  SimpleChanges,
  ViewChild,
} from '@angular/core';
import {
  CategoriaChart,
  CategoriaChartItem,
  ChartOptions,
} from '../../../../interfaces/Chart';
import { ChartComponent } from 'ng-apexcharts';

import Util from '../../../utils';

@Component({
  selector: 'fin-pie-chart-categoria',
  templateUrl: './pie-chart-categoria.component.html',
  styleUrls: ['./pie-chart-categoria.component.scss'],
})
export class PieChartCategoriaComponent implements OnInit, OnChanges {
  @Input() chartData!: CategoriaChart;
  
  @ViewChild('chart') chart!: ChartComponent;
  protected chartOptions!: Partial<ChartOptions> | any;


  ngOnInit(): void {
    if (this.chartData) {
      this.configPieCharts();
    } else {
      console.error('chartOptions is not provided');
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    const isEqual = Util.objectCompare(changes['chartData'].currentValue, changes['chartData'].previousValue)

    if (changes['chartData'] && isEqual) {
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
        width: 375,
        type: 'pie',
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
              return Util.numToCurrency(val);
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
