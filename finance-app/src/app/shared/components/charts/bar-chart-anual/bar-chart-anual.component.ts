import {
  Component,
  Input,
  OnChanges,
  OnDestroy,
  OnInit,
  SimpleChanges,
} from '@angular/core';
import Util from '../../../utils';
import { ChartOptions } from 'chart.js';

@Component({
  selector: 'fin-bar-chart-anual',
  templateUrl: './bar-chart-anual.component.html',
  styleUrl: './bar-chart-anual.component.scss',
})
export class BarChartAnualComponent implements OnInit, OnChanges {
  @Input() chartData!: any;
  protected chartOptions!: Partial<ChartOptions> | any;

  ngOnInit(): void {
    if (this.chartData) {
      this.configPieCharts();
    } else {
      console.error('chartOptions is not provided');
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (
      changes['chartData'] &&
      changes['chartData'].currentValue &&
      changes['chartData'].previousValue
    ) {
      this.configPieCharts();
    }
  }

  private configPieCharts() {
    const entradas = this.chartData.map((data: any) => data.entradas);
    const saidas = this.chartData.map((data: any) => data.saidas);

    this.chartOptions = {
      series: [
        {
          name: 'Saídas',
          data: saidas,
        },
        {
          name: 'Entradas',
          data: entradas,
        },
      ],
      legend: {
        fontSize: '14px',
        horizontalAlign: 'center',
        position: 'bottom',
        labels: {
          colors: '#dedede',
        },
      },
      chart: {
        type: 'bar',
        height: 275,
        toolbar: {
          show: false,
        },
      },
      grid: {
        show: false,
      },
      plotOptions: {
        bar: {
          horizontal: false,
          columnWidth: '80%',
          borderRadius: 5,
          borderRadiusApplication: 'end',
          endingShape: 'rounded',
        },
      },
      dataLabels: {
        enabled: false,
      },
      stroke: {
        show: true,
        width: 4,
        colors: ['transparent'],
      },
      xaxis: {
        categories: [
          'Jan',
          'Fev',
          'Mar',
          'Abr',
          'Mai',
          'Jun',
          'Jul',
          'Ago',
          'Set',
          'Out',
          'Nov',
          'Dez',
        ],
        labels: {
          style: {
            colors: [
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
              '#dedede',
            ],
          },
        },
        axisTicks: {
          show: false,
        },
      },
      colors: ['#780000', '#386641'],
      yaxis: {
        labels: {
          formatter: (val: any) => Util.numToCurrency(val),
          style: {
            colors: ['#dedede'],
          },
        },
      },
      fill: {
        opacity: 1,
      },
      tooltip: {
        y: {
          formatter: (val: any) => Util.numToCurrency(val),
        },
        theme: 'dark',
      },
    };
  }
}
