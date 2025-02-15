import { ChangeDetectionStrategy, Component, input } from '@angular/core';

@Component({
    selector: 'coinz-alert-container',
    templateUrl: './alert-container.component.html',
    styleUrl: './alert-container.component.scss',
    changeDetection: ChangeDetectionStrategy.OnPush,
    standalone: true
})
export class AlertContainerComponent {
  public message = input.required<string>();
}
