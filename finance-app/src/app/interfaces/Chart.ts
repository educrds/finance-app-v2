import { ApexNonAxisChartSeries, ApexChart, ApexResponsive, ApexOptions } from "ng-apexcharts";

export interface CategoriaChartItem{
  name: string;
  value: number;
  cor: string;
}

type BarChartKeys = 'entradas' | 'saidas';

export type CategoriesGroupedByType = Record<BarChartKeys, CategoriaChartItem>

export type ChartOptions = {
  series: ApexNonAxisChartSeries;
  chart: ApexChart;
  responsive: ApexResponsive[];
  labels: any;
  options: ApexOptions;
  colors: string[];
};

export type BarChartResult = Array<Record<BarChartKeys, number>>