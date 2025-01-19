import { Component, OnInit, WritableSignal, signal } from "@angular/core";
import { Transacao } from "../../models/Transacao";
import { TransacoesSoma } from "../../models/TransacoesSoma";
import { BaseTransacaoDirective } from "../../directives/base-transacao.directive";
import { BarChartResult, CategoriesGroupedByType } from "../../models/Chart";
import { faLevelDownAlt, faLevelUpAlt, faWallet } from "@fortawesome/free-solid-svg-icons";
import CoreUtil from "../../utils";
import { Icon } from "../../models/Icon";
import { ColumnComponent } from "../../../shared/components/column/column.component";
import { RowComponent } from "../../../shared/components/row/row.component";
import { TopCardComponent } from "../top-card/top-card.component";
import { AccordionModule } from "primeng/accordion";
import { PieChartCategoriaComponent } from "../pie-chart-categoria/pie-chart-categoria.component";
import { BarChartAnualComponent } from "../bar-chart-anual/bar-chart-anual.component";
import { WrapContainerComponent } from "../wrap-container/wrap-container.component";
import { NgClass, KeyValuePipe } from "@angular/common";
import { TransacaoTableComponent } from "../transacao-table/transacao-table.component";

@Component({
    selector: "fin-main",
    templateUrl: "./main.component.html",
    styleUrls: ["./main.component.scss"],
    standalone: true,
    imports: [
        ColumnComponent,
        RowComponent,
        TopCardComponent,
        AccordionModule,
        PieChartCategoriaComponent,
        BarChartAnualComponent,
        WrapContainerComponent,
        NgClass,
        TransacaoTableComponent,
        KeyValuePipe,
    ],
})
export class MainComponent extends BaseTransacaoDirective implements OnInit {
  protected iconsCard: Icon = { entrada: faLevelUpAlt, saldo: faWallet, saida: faLevelDownAlt };
  protected somatorio: WritableSignal<TransacoesSoma> = signal({
    soma_receitas: 0,
    soma_despesas: 0,
    saldo: 0,
  });

  // charts
  protected transacoesPorCategoria!: CategoriesGroupedByType;
  protected comparativoAnual: BarChartResult | undefined;
  protected saidasPorMetodo: any;

  protected override afterFetchTransacoes(transacoes: Transacao[]): void {
    this._updateSomatorio(transacoes);
    this._updateCharts(transacoes);
    this._getComparativoChartResult();
    this._getTransacaoesPorMetodo(transacoes);
  }

  protected sumSelected(transactions: Transacao[]): number {
    return transactions.reduce((acc: number, transacao: Transacao) => acc + transacao.trs_valor, 0);
  }

  private _getTransacaoesPorMetodo(transacoes: Transacao[]): void {
    this.saidasPorMetodo = CoreUtil.orderByMetodo(transacoes);
    console.log(this.saidasPorMetodo);
  }

  private _getComparativoChartResult(): void {
    this._transacoesService.getComparativoChart$(this.queryParams()).subscribe({
      next: (res: BarChartResult) => (this.comparativoAnual = res),
      error: err => this._messagesService.showError(err),
    });
  }

  // Atualizando a soma das transações.
  private _updateSomatorio(transacoes: Transacao[]): void {
    const somatorio = this._transacaoUtilService.obterSomatorioTransacoes(transacoes);
    const saldo = somatorio["soma_receitas"] - somatorio["soma_despesas"];
    
    this.somatorio.set({...somatorio, saldo: saldo});
  }

  // Atualizando os dados dos gráficos
  private _updateCharts(transacoes: Transacao[]): void {
    this.transacoesPorCategoria = CoreUtil.calcularSomatorioPorCategoria(transacoes);
  }
}
