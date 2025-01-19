import { Component } from '@angular/core';
import { ColumnComponent } from '../../../shared/components/column/column.component';
import { NavbarComponent } from '../../components/navbar/navbar.component';
import { RowComponent } from '../../../shared/components/row/row.component';
import { SidebarComponent } from '../../components/sidebar/sidebar.component';
import { RouterOutlet } from '@angular/router';

@Component({
    selector: 'fin-home',
    templateUrl: './home.component.html',
    styleUrl: './home.component.scss',
    standalone: true,
    imports: [ColumnComponent, NavbarComponent, RowComponent, SidebarComponent, RouterOutlet]
})
export class HomeComponent {

}
