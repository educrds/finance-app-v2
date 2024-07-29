import { Transacao } from "../../core/models/Transacao";

export default class SharedUtil {
  static numToCurrency(value: number | string): string {
    return value.toLocaleString("pt-BR", {
      style: "currency",
      currency: "BRL",
      minimumFractionDigits: 2,
    });
  }

  static isObjectEquals(prev: unknown, current: unknown): boolean {
    if (prev !== undefined && current !== undefined) {
      return JSON.stringify(prev) !== JSON.stringify(current);
    }
    return false;
  }

  static checkStatusUtil(transacao: Transacao): string {
    const statusMap: { [key: number]: string[] } = {
      1: ["A Receber", "Recebida"],
      2: ["A Pagar", "Paga"],
    };

    return statusMap[transacao.id_tipo_transacao]?.[transacao.trs_status] || "";
  }
}
