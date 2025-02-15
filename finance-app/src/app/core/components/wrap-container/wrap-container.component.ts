import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { NgClass } from '@angular/common';

@Component({
    selector: 'coinz-wrap-container',
    templateUrl: './wrap-container.component.html',
    styleUrl: './wrap-container.component.scss',
    changeDetection: ChangeDetectionStrategy.OnPush,
    standalone: true,
    imports: [NgClass]
})
export class WrapContainerComponent {
  public className = input<string | undefined>();
}
