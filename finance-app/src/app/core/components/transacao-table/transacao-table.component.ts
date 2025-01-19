import { ChangeDetectionStrategy, Component, ElementRef, Input, OnInit, ViewChild, WritableSignal, inject } from "@angular/core";
import { Transacao } from "../../models/Transacao";
import { Table, TableModule } from "primeng/table";
import { TransacaoUtilService } from "../../services/transacao-util.service";
import SharedUtil from "../../../shared/utils";
import { CategoriasService } from "../../services/categorias.service";
import { Observable } from "rxjs";
import { IDropdown } from "../../models/Dropdown";
import { SelectionIntervalRowsDirective } from "../../directives/selection-interval-rows.directive";
import { PrimeTemplate } from "primeng/api";
import { InputTextModule } from "primeng/inputtext";
import { ButtonDirective } from "primeng/button";
import { NgClass, NgStyle, CurrencyPipe, DatePipe } from "@angular/common";
import { AlertContainerComponent } from "../alert-container/alert-container.component";
import { SplitButtonModule } from "primeng/splitbutton";

@Component({
    selector: "fin-transacao-table",
    templateUrl: "./transacao-table.component.html",
    styleUrl: "./transacao-table.component.scss",
    changeDetection: ChangeDetectionStrategy.OnPush,
    standalone: true,
    imports: [TableModule, SelectionIntervalRowsDirective, PrimeTemplate, InputTextModule, ButtonDirective, NgClass, NgStyle, AlertContainerComponent, CurrencyPipe, DatePipe, SplitButtonModule]
})
export class TransacaoTableComponent implements OnInit {
  @ViewChild("dt") dt: Table | undefined;
  @ViewChild("inputSearch") inputSearch: ElementRef | undefined;

  @Input() transacoes: Transacao[] = [];
  @Input() rowSelected: Transacao[] = [];

  protected categoriasOptions$!: Observable<IDropdown[]>;

  private _transacaoUtilService = inject(TransacaoUtilService);
  private _categoriasService = inject(CategoriasService);

  ngOnInit(): void {
    // this.categoriasOptions$ = this._categoriasService.getCategoriasDropdown$();
  }

  protected clear(table: Table): void {
    if (this.inputSearch) {
      this.inputSearch.nativeElement.value = null;
    }
    table.clear();
  }

  protected applyFilterGlobal($event: any, stringVal: any): void {
    this.dt!.filterGlobal(($event.target as HTMLInputElement).value, stringVal);
  }

  protected updateSelectionRows(newSelection: Transacao[]): void {
    this.rowSelected = newSelection;
  }

  // configurando gráfico de pizza com dados já modelados
  protected sumSelected(transactions: any): number {
    return transactions.reduce((acc: number, transacao: Transacao) => acc + transacao.trs_valor, 0);
  }

  protected editarTransacao(transacao: Transacao): void {
    this._transacaoUtilService.editarTransacaoUtil(transacao);
  }

  protected deletarTransacao(transacao: Transacao): void {
    this._transacaoUtilService.deletarTransacaoUtil(transacao);
  }

  protected deletarTransacoes(): void {
    if (this.rowSelected) {
      const transacoesIds = this.rowSelected.map((item) => item.trs_id);
      this._transacaoUtilService.deletarTransacoesUtil(transacoesIds);
    }
  }

  protected checkStatus(transacao: Transacao): string {
    return SharedUtil.checkStatusUtil(transacao);
  }
}
