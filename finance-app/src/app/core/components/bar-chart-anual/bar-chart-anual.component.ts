import { ChangeDetectionStrategy, Component, Input, OnChanges, SimpleChanges } from "@angular/core";
import SharedUtil from "../../../shared/utils";
import { ChartOptions } from "chart.js";

@Component({
  selector: "fin-bar-chart-anual",
  templateUrl: "./bar-chart-anual.component.html",
  styleUrl: "./bar-chart-anual.component.scss",
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class BarChartAnualComponent implements OnChanges {
  @Input() chartData!: any;
  protected chartOptions!: Partial<ChartOptions> | any;

  ngOnChanges(changes: SimpleChanges): void {
    if ("chartData" in changes) {
      this.chartOptions = undefined; // Resetar opções para forçar a re-renderização
      this.configPieCharts();
    }
  }

  private _getChartSeries(chartData: any) {
    const entradas = chartData.map((data: any) => data.entradas);
    const saidas = chartData.map((data: any) => data.saidas);

    return { saidas, entradas };
  }

  private configPieCharts() {
    const { saidas, entradas } = this._getChartSeries(this.chartData);

    this.chartOptions = {
      series: [
        {
          name: "Saídas",
          data: saidas,
        },
        {
          name: "Entradas",
          data: entradas,
        },
      ],
      legend: {
        fontSize: "14px",
        horizontalAlign: "center",
        position: "bottom",
        labels: {
          colors: "#dedede",
        },
      },
      chart: {
        type: "bar",
        height: 255,
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
          columnWidth: "80%",
          borderRadius: 5,
          borderRadiusApplication: "end",
          endingShape: "rounded",
        },
      },
      dataLabels: {
        enabled: false,
      },
      stroke: {
        show: true,
        width: 4,
        colors: ["transparent"],
      },
      xaxis: {
        categories: ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"],
        labels: {
          style: {
            colors: [
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
              "#dedede",
            ],
          },
        },
        axisTicks: {
          show: false,
        },
      },
      colors: ["#780000", "#386641"],
      yaxis: {
        labels: {
          formatter: (val: any) => SharedUtil.numToCurrency(val),
          style: {
            colors: ["#dedede"],
          },
        },
      },
      fill: {
        opacity: 1,
      },
      tooltip: {
        y: {
          formatter: (val: any) => SharedUtil.numToCurrency(val),
        },
        theme: "dark",
      },
    };
  }
}
