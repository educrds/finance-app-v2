import { Component, OnInit } from '@angular/core';
import { TransacoesService } from './services/transacoes.service';
import { take } from 'rxjs';

@Component({
  selector: 'fin-root',
  templateUrl: './app.component.html',
  styleUrl: './app.component.scss',
})
export class AppComponent implements OnInit {
  title = 'finance-app';

  constructor(private _transacoesService: TransacoesService) {}

  ngOnInit(): void {
    this._transacoesService
      .getTransacoes()
      .pipe(take(1))
      .subscribe({
        next: (res) => console.log(res),
        error: (err) => console.log(err),
      });
  }
}
