import { Component, OnInit, WritableSignal, signal } from '@angular/core';
import { MenuItem } from 'primeng/api';
import { StorageService } from '../../shared/services/storage.service';
import Util from '../../shared/utils';
import { DatePickerService } from '../../services/date-picker.service';
@Component({
  selector: 'fin-navbar',
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.scss',
})
export class NavbarComponent implements OnInit {
  protected menuBarItems: MenuItem[] | undefined;
  protected userInitials: string | undefined;
  protected month_selected: WritableSignal<Date> = signal(new Date());

  constructor(
    private _datePickerService: DatePickerService,
    private _storageService: StorageService
  ) {}

  ngOnInit(): void {
    this.userInitials = Util.getUserNameInitials(this._storageService);
    this._datePickerService.datePickerObservable$.subscribe({
      next: (data) => this.month_selected.set(data)
    })

    this.menuBarItems = [
      {
        label: 'Sair',
        icon: 'pi pi-power-off',
        command: () => this._storageService.clearAndRefreshPage(),
      },
    ];
  }

  protected onDateChange(date: Date){
    this._datePickerService.notifyDateChanges(date)
  }
}
