import { ChangeDetectionStrategy, Component, ElementRef, Input, OnChanges, SimpleChanges, ViewChild, WritableSignal, inject, input, signal, viewChild } from "@angular/core";
import { Transacao } from "../../models/Transacao";
import { Table, TableModule } from "primeng/table";
import { TransacaoUtilService } from "../../services/transacao-util.service";
import SharedUtil from "../../../shared/utils";
import { SelectionIntervalRowsDirective } from "../../directives/selection-interval-rows.directive";
import { MenuItem, PrimeTemplate } from "primeng/api";
import { InputTextModule } from "primeng/inputtext";
import { Button, ButtonDirective } from "primeng/button";
import { NgClass, NgStyle, CurrencyPipe, DatePipe } from "@angular/common";
import { AlertContainerComponent } from "../alert-container/alert-container.component";
import { SplitButtonModule } from "primeng/splitbutton";
import { IconField } from "primeng/iconfield";
import { InputIcon } from "primeng/inputicon";
import { Select } from 'primeng/select';
import { FormsModule } from "@angular/forms";
import { Menu } from "primeng/menu";

@Component({
  selector: "coinz-transacao-table",
  templateUrl: "./transacao-table.component.html",
  styleUrl: "./transacao-table.component.scss",
  changeDetection: ChangeDetectionStrategy.OnPush,
  standalone: true,
  imports: [
    IconField,
    InputIcon,
    TableModule,
    SelectionIntervalRowsDirective,
    PrimeTemplate,
    InputTextModule,
    ButtonDirective,
    NgClass,
    NgStyle,
    Select,
    AlertContainerComponent,
    CurrencyPipe,
    DatePipe,
    SplitButtonModule,
    FormsModule,
    Button, 
    Menu
  ],
})
export class TransacaoTableComponent implements OnChanges {
  @ViewChild("dt") dt: Table | undefined;
  @ViewChild("inputSearch") inputSearch: ElementRef | undefined;

  @Input() transacoes: Transacao[] = [];
  @Input() rowSelected: Transacao[] = [];

  protected categoriasOptions: WritableSignal<string[]> = signal([]);
  protected selectedTransacao: WritableSignal<Transacao | null> = signal(null);
  protected selectedCategory: string | null = null;
  protected items_actions_transacao: MenuItem[] = [];

  protected metodosOptions: WritableSignal<string[]> = signal([]);
  protected selectedMetodo: string | null = null;

  private _transacaoUtilService = inject(TransacaoUtilService);

  constructor(){
    this.items_actions_transacao = [
      {
        label: "Editar",
        command: () => this.editarTransacao(this.selectedTransacao()),
      },
      {
        label: "Excluir",
        command: () => this.deletarTransacao(this.selectedTransacao()),
      },
    ];
  }

  ngOnChanges(changes: SimpleChanges): void {
    if(changes["transacoes"] && changes["transacoes"].currentValue.length){
      this.categoriasOptions.set([...new Set(this.transacoes.map((i) => i.categoria_nome))]);
      this.metodosOptions.set([...new Set(this.transacoes.map((i) => i.metodo_nome))]);
    }
  }

  protected openMenu(event: MouseEvent, transacao: Transacao, menu: Menu) {
    this.selectedTransacao.set(transacao);
    menu.toggle(event);
  }

  protected clear(table: Table): void {
    if (this.inputSearch) {
      this.inputSearch.nativeElement.value = null;
    }
    table.clear();
  }
  

  protected applyFilterGlobal($event: Event | string, stringVal: string = "contains"): void {
    const value = $event instanceof InputEvent && $event.target instanceof HTMLInputElement
      ? $event.target.value 
      : $event;
    this.dt!.filterGlobal(value, stringVal);
  }

  protected updateSelectionRows(newSelection: Transacao[]): void {
    this.rowSelected = newSelection;
  }

  // configurando gráfico de pizza com dados já modelados
  protected sumSelected(transactions: Transacao[]): number {
    return transactions.reduce((acc: number, transacao: Transacao) => acc + transacao.trs_valor, 0);
  }

  protected editarTransacao(transacao: Transacao | null): void {
    this._transacaoUtilService.editarTransacaoUtil(transacao);
  }

  protected deletarTransacao(transacao: Transacao | null): void {
    this._transacaoUtilService.deletarTransacaoUtil(transacao);
  }

  protected deletarTransacoes(): void {
    if (this.rowSelected) {
      const transacoesIds = this.rowSelected.map(item => item.trs_id);
      this._transacaoUtilService.deletarTransacoesUtil(transacoesIds);
    }
  }

  protected checkStatus(transacao: Transacao): string {
    return SharedUtil.checkStatusUtil(transacao);
  }
}
