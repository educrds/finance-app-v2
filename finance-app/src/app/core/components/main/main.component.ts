import { Component, OnInit, WritableSignal, signal } from "@angular/core";
import { Transacao } from "../../models/Transacao";
import { TransacoesSoma } from "../../models/TransacoesSoma";
import { BaseTransacaoDirective } from "../../directives/base-transacao.directive";
import { BarChart, CategoriesGroupedByType } from "../../models/Chart";
import CoreUtil from "../../utils";
import { ColumnComponent } from "../../../shared/components/column/column.component";
import { RowComponent } from "../../../shared/components/row/row.component";
import { TopCardComponent } from "../top-card/top-card.component";
import { PieChartCategoriaComponent } from "../pie-chart-categoria/pie-chart-categoria.component";
import { BarChartAnualComponent } from "../bar-chart-anual/bar-chart-anual.component";
import { WrapContainerComponent } from "../wrap-container/wrap-container.component";
import { NgClass, KeyValuePipe, AsyncPipe } from "@angular/common";
import { TransacaoTableComponent } from "../transacao-table/transacao-table.component";
import { AccordionModule } from 'primeng/accordion';
import { TabsModule } from 'primeng/tabs';
import { TableHeaderComponent } from "../../../shared/components/table-header/table-header.component";

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
        TabsModule,
        AsyncPipe,
        TableHeaderComponent
    ],
})
export class MainComponent extends BaseTransacaoDirective implements OnInit {
  protected somatorio: WritableSignal<TransacoesSoma> = signal({
    soma_receitas: 0,
    soma_despesas: 0,
    saldo: 0,
  });

  // charts
  protected transacoesPorCategoria!: CategoriesGroupedByType;
  protected comparativoAnual!: BarChart[];
  protected saidasPorMetodo!: CategoriesGroupedByType;

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
  }

  private _getComparativoChartResult(): void {
    this._transacoesService.getComparativoChart$(this.queryParams()).subscribe({
      next: (chartResult: BarChart[]) => (this.comparativoAnual = chartResult),
      error: err => this._messagesService.showError(err),
    });
  }

  // Atualizando a soma das transações.
  private _updateSomatorio(transacoes: Transacao[]): void {
    const somatorio = this._transacaoUtilService.obterSomatorioTransacoes(transacoes);
    const saldo = somatorio["soma_receitas"] - somatorio["soma_despesas"];
    
    this.somatorio.set({...somatorio, saldo});
  }

  // Atualizando os dados dos gráficos
  private _updateCharts(transacoes: Transacao[]): void {
    this.transacoesPorCategoria = CoreUtil.calcularSomatorioPorCategoria(transacoes);
  }
}
