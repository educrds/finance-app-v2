interface Dataset {
  data: number[];
  backgroundColor?: string[];
}
export interface ConfigCategoriaChart {
  labels: string[];
  datasets: Dataset[];
}