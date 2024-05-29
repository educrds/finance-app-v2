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

interface Dataset {
  data: number[];
  backgroundColor?: string[];
}
export interface ConfigCategoriaChart {
  labels: string[];
  datasets: Dataset[];
}