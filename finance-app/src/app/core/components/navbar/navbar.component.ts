import { Component, OnInit, WritableSignal, signal } from '@angular/core';
import { MenuItem } from 'primeng/api';
import { DatePickerService } from '../../services/date-picker.service';
import { NavigationEnd, Router } from '@angular/router';
import { Observable, filter, map, startWith } from 'rxjs';
import { StorageService } from '../../../shared/services/storage.service';
import Util from '../../../shared/utils';
@Component({
  selector: 'fin-navbar',
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.scss',
})
export class NavbarComponent implements OnInit {
  protected menuBarItems: MenuItem[] | undefined;
  protected userInitials: string | undefined;
  protected month_selected: WritableSignal<Date> = signal(new Date());

  canShowDatePicker$!: Observable<boolean>;
  navigationEvents$!: Observable<NavigationEnd>;

  constructor(
    private _datePickerService: DatePickerService,
    private _storageService: StorageService,
    private _router: Router,
  ) {}

  ngOnInit(): void {
    this.navigationEvents$ = this._router.events.pipe(
      filter(event => event instanceof NavigationEnd),
      map(event => event as NavigationEnd) 
    );
    this.canShowDatePicker$ = this.navigationEvents$.pipe(
       startWith(true),
       map(event => {
        if(typeof event === 'boolean'){
          return event;
        }
        return this.checkRoute(event.url)
      })
    );

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

  private checkRoute(url: string) {
    return !url.includes('/categorias');
  }

  protected onDateChange(date: Date){
    this._datePickerService.notifyDateChanges(date)
  }
}
