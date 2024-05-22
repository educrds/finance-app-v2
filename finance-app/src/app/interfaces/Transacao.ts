export type Transacao = {
  trs_data_ocorrido: Date;
  trs_valor: number;
  trs_titulo: string;
  trs_tipo: number;
  trs_id: number;
  trs_status: number;
  categoria_nome: string;
  id_categoria: number;
  categoria_cor: string;
  metodo_nome: string;
  metodo_id: number;
  tipo_transacao: string;
  id_tipo_transacao: number;
  trs_parcelado: number;
};
