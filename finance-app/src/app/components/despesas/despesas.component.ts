import { Component } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { ITransacao } from '../../interfaces/ITransacao';
import { take } from 'rxjs';
import { DateFilterService } from '../../services/date-filter.service';

@Component({
  selector: 'fin-despesas',
  templateUrl: './despesas.component.html',
  styleUrl: './despesas.component.scss',
})
export class DespesasComponent {
  protected transacoes: ITransacao[] = [];
  private queryParams: Date = new Date();

  constructor(
    private _transacoesService: TransacoesService,
    private _dateFilterService: DateFilterService
  ) {}

  ngOnInit(): void {
    this.getDespesas();
    this._dateFilterService.notifyObservable$.subscribe((res) => {
      const { date } = res;
      if (date) {
        this.queryParams = date;
        this.getDespesas();
      }
    });
  }

  private getDespesas() {
    this._transacoesService
      .getDespesas(this.queryParams)
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.transacoes = res),
        error: (err) => console.log(err),
      });
  }
}
