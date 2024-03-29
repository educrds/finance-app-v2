import { Component, OnInit } from '@angular/core';
import { TransacoesService } from '../../services/transacoes.service';
import { take, tap } from 'rxjs';
import { ITransacao } from '../../interfaces/ITransacao';

@Component({
  selector: 'fin-main',
  templateUrl: './main.component.html',
  styleUrl: './main.component.scss',
})
export class MainComponent implements OnInit {
  protected transacoes: ITransacao[] = [];

  constructor(private _transacoesService: TransacoesService) {}

  ngOnInit(): void {
    this._transacoesService
      .getTransacoes()
      .pipe(take(1))
      .subscribe({
        next: (res) => (this.transacoes = res),
        error: (err) => console.log(err),
      });
  }
}