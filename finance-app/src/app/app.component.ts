import { Component, OnInit } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { PrimeNG } from 'primeng/config';
import Lara from '@primeng/themes/lara';

@Component({
    selector: 'fin-root',
    templateUrl: './app.component.html',
    standalone: true,
    imports: [
        RouterOutlet,
        ToastModule,
        ConfirmDialogModule,
    ],
})
export class AppComponent implements OnInit {
  constructor(private _config: PrimeNG) {}

  ngOnInit(): void {
    this._config.ripple.set(true);
    this._config.theme.set({ preset: Lara })
    this._config.setTranslation({
      accept: 'Sim',
      reject: 'Não',
      dayNames: [
        'Domingo',
        'Segunda',
        'Terça',
        'Quarta',
        'Quinta',
        'Sexta',
        'Sábado',
      ],
      dayNamesShort: ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sab'],
      dayNamesMin: ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sab'],
      monthNames: [
        'Janeiro',
        'Fevereiro',
        'Março',
        'Abril',
        'Maio',
        'Junho',
        'Julho',
        'Agosto',
        'Setembro',
        'Outubro',
        'Novembro',
        'Dezembro',
      ],
      monthNamesShort: [
        'Jan',
        'Fev',
        'Mar',
        'Abr',
        'Mai',
        'Jun',
        'Jul',
        'Ago',
        'Set',
        'Out',
        'Nov',
        'Dez',
      ],
      dateFormat: 'dd/mm/yy'
    });
  }
}
