import { ApexNonAxisChartSeries, ApexChart, ApexResponsive, ApexOptions } from "ng-apexcharts";

export interface CategoriaChartItem {
  name: string;
  value: number;
  cor: string;
}

export interface CategoriaChart {
  [key: string]: CategoriaChartItem;
}

export interface CategoriesGroupedByType {
  entrada: {[key: string]: CategoriaChartItem},
  saida: {[key: string]: CategoriaChartItem},
}

export type ChartOptions = {
  series: ApexNonAxisChartSeries;
  chart: ApexChart;
  responsive: ApexResponsive[];
  labels: any;
  options: ApexOptions;
  colors: string[];
};