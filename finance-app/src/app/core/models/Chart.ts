import { ApexNonAxisChartSeries, ApexChart, ApexResponsive, ApexOptions } from "ng-apexcharts";

export interface CategoriaChartItem {
  name: string;
  value: number;
  cor: string;
}

export type BarChartKeys = keyof Pick<BarChart, "entradas" | "saidas">;

export type CategoriesGroupedByType = { [key: string]: CategoriaChartItem };

export type ChartOptions = {
  series: ApexNonAxisChartSeries;
  chart: ApexChart;
  responsive: ApexResponsive[];
  labels: any;
  options: ApexOptions;
  colors: string[];
};

export type BarChartResult = Array<Pick<BarChart, BarChartKeys>>;
export type BarChart = {
  entradas: number;
  saidas: number;
  trs_mes_ocorrido: number;
};
