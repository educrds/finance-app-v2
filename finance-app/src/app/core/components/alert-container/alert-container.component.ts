import { ChangeDetectionStrategy, Component, input } from '@angular/core';

@Component({
  selector: 'fin-alert-container',
  templateUrl: './alert-container.component.html',
  styleUrl: './alert-container.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AlertContainerComponent {
  public message = input.required<string>();
}
