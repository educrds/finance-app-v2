import { Component } from '@angular/core';
import { ITransacao } from '../../interfaces/ITransacao';
import { TransacoesService } from '../../services/transacoes.service';
import { take } from 'rxjs';

@Component({
  selector: 'fin-receitas',
  templateUrl: './receitas.component.html',
  styleUrl: './receitas.component.scss'
})
export class ReceitasComponent {
  protected transacoes: ITransacao[] = [];

  constructor(private _transacoesService: TransacoesService) {}

  ngOnInit(): void {
    this._transacoesService
      .getReceitas()
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.transacoes = res),
        error: (err) => console.log(err),
      });
  }
}
