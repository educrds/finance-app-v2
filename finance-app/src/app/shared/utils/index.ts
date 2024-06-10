import { CategoriesGroupedByType } from '../../interfaces/Chart';
import { Transacao } from '../../interfaces/Transacao';
import { StorageService } from '../services/storage.service';

export default class Util {  
  static getUserNameInitials(storageService: StorageService): string | undefined {
    const user = storageService.getUser();
    if (user) {
      let rgx = new RegExp(/(\p{L}{1})\p{L}+/, 'gu');

      const arrayName = [...user.name.matchAll(rgx)] || [];
      const firstLetter = arrayName.shift()?.[1] || '';
      const secondLetter = arrayName.pop()?.[1] || '';

      const initials = (firstLetter + secondLetter).toUpperCase();
      return initials;
    }
    return 'X';
  }

  // cálculo de transacoes por categoria e tipo para configurar gráfico de pizza
  static calcularSomatorioPorCategoria(transacoes: Transacao[] | any[]): CategoriesGroupedByType {
    return transacoes.reduce(
      (acc, transacao) => {
        const { categoria_cor, categoria_nome, trs_valor, id_tipo_transacao } =
          transacao;
        const tipoTransacao = id_tipo_transacao === 1 ? 'entrada' : 'saida';

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
      { entrada: {}, saida: {} }
    );
  }

  static numToCurrency(value: number | string): string {
    return value.toLocaleString('pt-BR', {
      style: 'currency',
      currency: 'BRL',
      minimumFractionDigits: 2,
    });
  }

  static objectCompare(prev: Object, current: Object): boolean {
    if (prev !== undefined && current !== undefined) {
      return JSON.stringify(prev) !== JSON.stringify(current);
    }
    return false;
  }
}
