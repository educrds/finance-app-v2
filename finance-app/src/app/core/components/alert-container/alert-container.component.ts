import { Component, Input } from '@angular/core';

@Component({
  selector: 'fin-alert-container',
  templateUrl: './alert-container.component.html',
  styleUrl: './alert-container.component.scss'
})
export class AlertContainerComponent {
  @Input() message!: string;
}
