import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { MenuItem } from 'primeng/api';
import { StorageService } from '../../shared/services/storage.service';
import { NotificationService } from '../../shared/services/notification.service';
import { User } from '../../interfaces/User';

@Component({
  selector: 'fin-navbar',
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.scss',
})
export class NavbarComponent implements OnInit {
  protected filterDateForm!: FormGroup;
  protected menuBarItems: MenuItem[] | undefined;
  protected userInitials!: string | undefined;

  constructor(
    private _fb: FormBuilder,
    private _notificationService: NotificationService,
    private _storageService: StorageService
  ) {}

  ngOnInit(): void {
    this.userInitials = this.getUserNameInitials();
    this.filterDateForm = this._fb.group({
      month_selected: this._fb.control(this.getCurrentMonthFormatted()),
    });

    this.filterDateForm.controls['month_selected'].valueChanges.subscribe(
      (date) => this._notificationService.notifyChanges({ date })
    );

    this.menuBarItems = [
      {
        label: 'Sair',
        icon: 'pi pi-power-off',
        command: () => {
          this._storageService.clearAndRefreshPage();
        },
      },
    ];
  }

  private getUserNameInitials() {
    const user = this._storageService.getUser();
    if (user) {
      let rgx = new RegExp(/(\p{L}{1})\p{L}+/, 'gu');

      const arrayName = [...user.name.matchAll(rgx)] || [];
      const firstLetter = (arrayName.shift()?.[1] || '');
      const secondLetter = (arrayName.pop()?.[1] || '');

      const initials = (firstLetter + secondLetter).toUpperCase();
      return initials;
    }
    return;
  }

  private getCurrentMonthFormatted() {
    const date = new Date();
    const year = date.getFullYear();
    const month = date.getMonth() + 1;

    const current_month = new Date(`${year}, ${month}, 01`);

    return current_month;
  }
}
