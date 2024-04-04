import { Component, Input } from '@angular/core';

@Component({
  selector: 'fin-top-card',
  templateUrl: './top-card.component.html',
  styleUrl: './top-card.component.scss'
})
export class TopCardComponent {
 @Input() title!: string;
 @Input() className!: string;
 @Input() value!: number;
 @Input() isCurrency!: boolean;
}
