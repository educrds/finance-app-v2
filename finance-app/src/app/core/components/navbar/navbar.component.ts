import { Component, OnInit, WritableSignal, inject, signal } from "@angular/core";
import { MenuItem } from "primeng/api";
import { DatePickerService } from "../../services/date-picker.service";
import { NavigationEnd, Router } from "@angular/router";
import { Observable, filter, map, startWith } from "rxjs";
import { StorageService } from "../../services/storage.service";
import CoreUtil from "../../utils";
import { WrapContainerComponent } from "../wrap-container/wrap-container.component";
import { LogoComponent } from "../../../shared/components/logo/logo.component";
import { CalendarModule } from "primeng/calendar";
import { FormsModule } from "@angular/forms";
import { AvatarModule } from "primeng/avatar";
import { MenuModule } from "primeng/menu";
import { AsyncPipe } from "@angular/common";
@Component({
    selector: "fin-navbar",
    templateUrl: "./navbar.component.html",
    styleUrl: "./navbar.component.scss",
    standalone: true,
    imports: [
        WrapContainerComponent,
        LogoComponent,
        CalendarModule,
        FormsModule,
        AvatarModule,
        MenuModule,
        AsyncPipe,
    ],
})
export class NavbarComponent implements OnInit {
  protected menuBarItems: MenuItem[] | undefined;
  protected userInitials: string | undefined;
  protected month_selected: WritableSignal<Date> = signal(new Date());
  protected isShowDatePicker$: Observable<boolean> | undefined;

  #navigationEvents$: Observable<NavigationEnd> | undefined;

  #_datePickerService = inject(DatePickerService);
  #_storageService = inject(StorageService);
  #_router = inject(Router);

  ngOnInit(): void {
    this.#navigationEvents$ = this.#_router.events.pipe(
      filter(event => event instanceof NavigationEnd),
      map(event => event as NavigationEnd)
    );
    this.isShowDatePicker$ = this.#navigationEvents$.pipe(
      startWith(true),
      map(event => {
        if (typeof event === "boolean") {
          return event;
        }
        return this.checkRoute(event.url);
      })
    );

    this.userInitials = CoreUtil.getUserNameInitials(this.#_storageService);
    this.#_datePickerService.datePickerObservable$.subscribe({
      next: data => this.month_selected.set(data),
    });

    this.menuBarItems = [
      {
        label: "Sair",
        icon: "pi pi-power-off",
        command: () => this.#_storageService.clearAndRefreshPage(),
      },
    ];
  }

  private checkRoute(url: string) {
    return !url.includes("/categorias");
  }

  protected onDateChange(date: Date) {
    this.#_datePickerService.notifyDateChanges(date);
  }
}
