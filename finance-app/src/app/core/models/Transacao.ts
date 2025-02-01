export type Transacao = {
  trs_data_ocorrido: string | Date;
  data_fm: string | Date;
  trs_ano_ocorrido: number;
  trs_mes_ocorrido: number;
  trs_id: number;
  trs_valor: number;
  trs_titulo: string;
  trs_status: number;
  categoria_nome: string;
  categoria_cor: string;
  id_categoria: number;
  metodo_nome: string;
  trs_metodo: string;
  metodo_id: number;
  tipo_transacao: string;
  id_tipo_transacao: number;
  trs_parcelado: number | boolean;
  par_id: number | null;
  trs_num_parcela: number | null;
  total_parcelas: number | null;
};

export type TransacaoForm = {
  trs_valor: number,
  trs_data_ocorrido: Date,
  trs_titulo: string,
  trs_categoria: string,
  trs_usuario: string,
  trs_metodo: string,
  trs_status: boolean,
  trs_parcelado: boolean,
  data_fim_repeticao: string,
}