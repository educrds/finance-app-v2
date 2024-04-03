import { Component, OnInit } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { TransacoesService } from '../../services/transacoes.service';
import { take } from 'rxjs';
import { DateFilterService } from '../../services/date-filter.service';

@Component({
  selector: 'fin-receitas',
  templateUrl: './receitas.component.html',
  styleUrl: './receitas.component.scss'
})
export class ReceitasComponent implements OnInit {
  protected transacoes: ITransacao[] = [];
  private queryParams: Date = new Date();

  constructor(private _transacoesService: TransacoesService, private _dateFilterService: DateFilterService) {}

  ngOnInit(): void {
    this.getReceitas();

    this._dateFilterService.notifyObservable$.subscribe((res) => {
      const { date } = res;
      if (date) {
        this.queryParams = date;
        this.getReceitas();
      }
    });
  }
  
  
  private getReceitas(){
    this._transacoesService
      .getReceitas(this.queryParams)
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.transacoes = res),
        error: (err) => console.log(err),
      });
  }
}
