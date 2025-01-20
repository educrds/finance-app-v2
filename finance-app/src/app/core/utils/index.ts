import { CategoriesGroupedByType } from "../models/Chart";
import { Transacao } from "../models/Transacao";
import { StorageService } from "../services/storage.service";

export default class CoreUtil {
  static getUserNameInitials(storageService: StorageService): string | undefined {
    const user = storageService.getUser();

    if (user && user.name) {
      const rgx = /\b(\p{L})/gu; // Captura apenas a primeira letra de cada palavra.
      const arrayName = [...user.name.matchAll(rgx)];
      
      const firstLetter = arrayName.shift()?.[0] || "";
      const secondLetter = arrayName.pop()?.[0] || "";

      const initials = (firstLetter + secondLetter).toUpperCase();
      return initials;
    }
    return "X";
  }

  static orderByMetodo(transacoes: Transacao[]): CategoriesGroupedByType {
    return transacoes.reduce((acc: CategoriesGroupedByType, transacao: Transacao) => {
      const { categoria_cor, metodo_nome, trs_valor, id_tipo_transacao } = transacao;
  
      // Filtra transações pelo tipo
      if (id_tipo_transacao !== 1) {
        // Verifica se o método já existe no acumulador
        if (!acc[metodo_nome]) {
          // Cria um novo objeto para o método
          acc[metodo_nome] = {
            name: metodo_nome,
            value: 0,
            cor: categoria_cor,
          };
        }
        
        // Soma o valor ao método existente
        acc[metodo_nome].value += trs_valor;
      }
  
      return acc;
    }, {});
  }
  
  
  // cálculo de transacoes por categoria e tipo para configurar gráfico de pizza
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static calcularSomatorioPorCategoria(transacoes: Transacao[] | any[]): CategoriesGroupedByType {
    return transacoes.reduce(
      (acc, transacao) => {
        const { categoria_cor, categoria_nome, trs_valor, id_tipo_transacao } = transacao;
        const tipoTransacao = id_tipo_transacao === 1 ? "entradas" : "saidas";

        const categoriaNome = categoria_nome;
        const categoriaCor = categoria_cor;
        const valor = trs_valor;

        // Cria o objeto de categoria se ainda não existir
        if (!acc[tipoTransacao][categoriaNome]) {
          acc[tipoTransacao][categoriaNome] = {
            name: categoriaNome,
            value: 0,
            cor: categoriaCor,
          };
        }

        // Soma o valor à categoria correspondente
        acc[tipoTransacao][categoriaNome].value += valor;

        return acc;
      },
      { entradas: {}, saidas: {} }
    );
  }
}
