import { AsyncPipe, DatePipe } from '@angular/common';
import { Component, inject, OnInit } from '@angular/core';
import { Observable, of } from 'rxjs';
import { Users } from '../../models/User';
import { UsersService } from '../../services/users.service';
import { Chip } from 'primeng/chip';

@Component({
  selector: 'coinz-users-list',
  standalone: true,
  imports: [AsyncPipe, DatePipe, Chip],
  templateUrl: './users-list.component.html',
  styleUrl: './users-list.component.scss'
})
export class UsersListComponent implements OnInit {
  protected usuarioList$: Observable<Users[]> = of([]);

  private _usuariosService = inject(UsersService)

  ngOnInit(): void {
    this.usuarioList$ = this._usuariosService.getUsersList$();
  }
}
