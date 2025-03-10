import { ChangeDetectionStrategy, Component, input, OnChanges, SimpleChanges } from "@angular/core";
import SharedUtil from "../../../shared/utils";
import { ChartOptions } from "chart.js";
import { ChartComponent } from "ng-apexcharts";
import { BarChart } from "../../models/Chart";

@Component({
    selector: "coinz-bar-chart-anual",
    templateUrl: "./bar-chart-anual.component.html",
    styleUrl: "./bar-chart-anual.component.scss",
    changeDetection: ChangeDetectionStrategy.OnPush,
    standalone: true,
    imports: [ChartComponent]
})
export class BarChartAnualComponent implements OnChanges {
  public chartData = input<BarChart[]>([]);
  protected chartOptions: Partial<ChartOptions> | any;

  ngOnChanges(changes: SimpleChanges): void {
    if ("chartData" in changes) {
      this.chartOptions = undefined; // Resetar opções para forçar a re-renderização
      this.configPieCharts();
    }
  }

  private _getChartSeries(chartData: BarChart[]): { saidas: number[], entradas: number[] } {
    const entradas = chartData.map(({ entradas }) => entradas);
    const saidas = chartData.map(({ saidas }) => saidas);
    return { saidas, entradas };
  }

  private configPieCharts() {
    const { saidas, entradas } = this._getChartSeries(this.chartData());
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
          formatter: (val: number) => SharedUtil.numToCurrency(val),
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
          formatter: (val: number) => SharedUtil.numToCurrency(val),
        },
        theme: "dark",
      },
    };
  }
}
