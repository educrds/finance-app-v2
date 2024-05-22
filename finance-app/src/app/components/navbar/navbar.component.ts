import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { MenuItem } from 'primeng/api';
import { StorageService } from '../../shared/services/storage.service';
import { NotificationService } from '../../shared/services/notification.service';
import Util from '../../shared/utils';
@Component({
  selector: 'fin-navbar',
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.scss',
})
export class NavbarComponent implements OnInit {
  protected filterDateForm!: FormGroup;
  protected menuBarItems: MenuItem[] | undefined;
  protected userInitials: string | undefined;

  constructor(
    private _fb: FormBuilder,
    private _notificationService: NotificationService,
    private _storageService: StorageService
  ) {}

  ngOnInit(): void {
    this.userInitials = Util.getUserNameInitials(this._storageService);
    this.filterDateForm = this._fb.group({
      month_selected: this._fb.control(this.getCurrentMonthFormatted()),
    });

    // Se houver mudanças no mês selecionado, notificará a service e, consequentemente, outros componentes
    this.filterDateForm.controls['month_selected'].valueChanges.subscribe(
      (date) => this._notificationService.notifyChanges({ date })
    );

    this.menuBarItems = [
      {
        label: 'Sair',
        icon: 'pi pi-power-off',
        command: () => this._storageService.clearAndRefreshPage(),
      },
    ];
  }

  private getCurrentMonthFormatted() {
    const date = new Date();
    return new Date(date.getFullYear(), date.getMonth(), 1);
  }
}
