import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { WrapContainerComponent } from '../wrap-container/wrap-container.component';
import { NgClass, CurrencyPipe } from '@angular/common';

@Component({
    selector: 'fin-top-card',
    templateUrl: './top-card.component.html',
    styleUrl: './top-card.component.scss',
    changeDetection: ChangeDetectionStrategy.OnPush,
    standalone: true,
    imports: [WrapContainerComponent, NgClass, CurrencyPipe]
})
export class TopCardComponent {
 public title = input<string>();
 public icon = input<string>();
 public value = input<number>(0);
 public isCurrency = input<boolean>(false);
}
