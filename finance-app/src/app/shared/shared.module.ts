import { NgModule } from "@angular/core";
import { CommonModule } from "@angular/common";
import { AlertContainerComponent } from "../core/components/alert-container/alert-container.component";
import { ColumnComponent } from "./components/column/column.component";
import { LogoComponent } from "./components/logo/logo.component";
import { RowComponent } from "./components/row/row.component";
import { TopCardComponent } from "../core/components/top-card/top-card.component";
import { WrapContainerComponent } from "../core/components/wrap-container/wrap-container.component";
import { BaseTransacaoDirective } from "../core/directives/base-transacao.directive";
import { TransacaoTableComponent } from "../core/components/transacao-table/transacao-table.component";
import { TableModule } from "primeng/table";
import { TooltipModule } from "primeng/tooltip";
import { ButtonModule } from "primeng/button";
import { InputTextModule } from "primeng/inputtext";
import { CategoriaTableComponent } from "../core/components/categoria-table/categoria-table.component";
import { TagModule } from "primeng/tag";
import { PieChartCategoriaComponent } from "../core/components/pie-chart-categoria/pie-chart-categoria.component";
import { ConfirmDialogModule } from "primeng/confirmdialog";
import { SelectionIntervalRowsDirective } from "../core/directives/selection-interval-rows.directive";
import { NgApexchartsModule } from "ng-apexcharts";
import { BarChartAnualComponent } from "../core/components/bar-chart-anual/bar-chart-anual.component";
import { ConfirmDialogComponent } from "./components/confirm-dialog/confirm-dialog.component";
import { FontAwesomeModule } from "@fortawesome/angular-fontawesome";
import { SplitButton, SplitButtonModule } from "primeng/splitbutton";

const SHARED_COMPONENTS = [
  AlertContainerComponent,
  ColumnComponent,
  LogoComponent,  
  RowComponent,
  TopCardComponent,
  WrapContainerComponent,
  TransacaoTableComponent,
  CategoriaTableComponent,
  PieChartCategoriaComponent,
  ConfirmDialogComponent,
  SelectionIntervalRowsDirective,
  BarChartAnualComponent,
  BaseTransacaoDirective,
];

@NgModule({
    imports: [
        CommonModule,
        TableModule,
        TooltipModule,
        ButtonModule,
        InputTextModule,
        TagModule,
        ConfirmDialogModule,
        NgApexchartsModule,
        FontAwesomeModule,
        ...SHARED_COMPONENTS,
    ],
    exports: [...SHARED_COMPONENTS],
})
export class SharedModule {}
