import { ChangeDetectionStrategy, Component, Input } from '@angular/core';

@Component({
  selector: 'fin-wrap-container',
  templateUrl: './wrap-container.component.html',
  styleUrl: './wrap-container.component.scss',
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class WrapContainerComponent {
  @Input() className: string | undefined;
}
