import { Component } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { ITransacao } from '../../interfaces/ITransacao';
import { take } from 'rxjs';

@Component({
  selector: 'fin-despesas',
  templateUrl: './despesas.component.html',
  styleUrl: './despesas.component.scss'
})
export class DespesasComponent {
  protected transacoes: ITransacao[] = [];

  constructor(private _transacoesService: TransacoesService) {}

  ngOnInit(): void {
    this._transacoesService
      .getDespesas()
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.transacoes = res),
        error: (err) => console.log(err),
      });
  }
}
