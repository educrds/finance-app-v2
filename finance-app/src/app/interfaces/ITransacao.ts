export interface ITransacao {
  trs_data_ocorrido: Date;
  trs_ano_ocorrido: number;
  trs_mes_ocorrido: number;
  trs_valor: number;
  trs_titulo: string;
  categoria_nome: string;
  id_categoria: number;
  categoria_cor: string;
  metodo: string;
  nome_usuario: string;
  tipo_transacao: string;
  id_tipo_transacao: number;
  trs_parcelado: number;
}
