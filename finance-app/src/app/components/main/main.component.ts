import { Component, OnInit, ViewChild } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { ITransacoesSoma } from '../../interfaces/ITransacoesSoma';
import { TransacaoUtilService } from '../../utils/transacao-util.service';
import { ParamsTransacao } from '../../interfaces/ParamsTransacao';
import { NotificationService } from '../../shared/services/notification.service';
import { Table } from 'primeng/table';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrl: './main.component.scss',
})
export class MainComponent implements OnInit {
  @ViewChild('dt') dt: Table | undefined;

  protected transacoes: ITransacao[] = [];
  protected somatorio!: ITransacoesSoma;
  protected rowSelected!: ITransacao[] | null;

  private queryParams: ParamsTransacao = {
    filterDate: new Date(),
  };

  constructor(
    private _notificationService: NotificationService,
    private _transacaoUtilService: TransacaoUtilService,
  ) {}

  ngOnInit(): void {
    this.fetchTransacoes(this.queryParams);

    this._notificationService.notifyObservable$.subscribe((res) => {
      if (res.refresh) {
        this.fetchTransacoes(this.queryParams);
      }
      this.rowSelected = null;
    });

    this._notificationService.notifyObservable$.subscribe((res) => {
      const { date } = res;
      if (date) {
        this.queryParams.filterDate = date;
        this.fetchTransacoes(this.queryParams);
      }
    });
  }
  
  clear(table: Table) {
    table.clear();
  }

  applyFilterGlobal($event: any, stringVal: any) {
    this.dt!.filterGlobal(($event.target as HTMLInputElement).value, stringVal);
  }

  protected deletarTransacoes() {
    if (this.rowSelected) {
      const transacoesIds = this.rowSelected.map((item) => item.trs_id);
      this._transacaoUtilService.deletarTransacoesUtil(transacoesIds);
    }
  }

  protected editarTransacao(transacao: ITransacao) {
    this._transacaoUtilService.editarTransacaoUtil(transacao);
  }

  protected deletarTransacao(idTransacao: number, isParcelado: boolean) {
    this._transacaoUtilService.deletarTransacaoUtil(idTransacao, isParcelado);
  }

  protected checkStatus(transacao: ITransacao): string {
    return this._transacaoUtilService.checkStatusUtil(transacao);
  }

  private fetchTransacoes(params: ParamsTransacao) {
    this._transacaoUtilService.getTransacoesUtil(params).subscribe({
      next: (transacoes: ITransacao[]) => {
        this.transacoes = transacoes;
        this.somatorio = this._transacaoUtilService.obterSomatorioTransacoes(
          this.transacoes
        );
      },
      error: (err) => console.log(err),
    });
  }
}
