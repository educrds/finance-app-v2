import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import { IconProp } from '@fortawesome/fontawesome-svg-core';
import { WrapContainerComponent } from '../wrap-container/wrap-container.component';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { NgClass, CurrencyPipe } from '@angular/common';

@Component({
    selector: 'fin-top-card',
    templateUrl: './top-card.component.html',
    styleUrl: './top-card.component.scss',
    changeDetection: ChangeDetectionStrategy.OnPush,
    standalone: true,
    imports: [WrapContainerComponent, FaIconComponent, NgClass, CurrencyPipe]
})
export class TopCardComponent {
 @Input() title!: string;
 @Input() icon!: IconProp;
 @Input() value!: number;
 @Input() isCurrency!: boolean;
}
