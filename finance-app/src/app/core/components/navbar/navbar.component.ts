import { Component, OnInit, WritableSignal, inject, signal } from "@angular/core";
import { MenuItem } from "primeng/api";
import { DatePickerService } from "../../services/date-picker.service";
import { Observable } from "rxjs";
import { StorageService } from "../../services/storage.service";
import CoreUtil from "../../utils";
import { LogoComponent } from "../../../shared/components/logo/logo.component";
import { DatePicker } from "primeng/datepicker";
import { FormsModule } from "@angular/forms";
import { Avatar } from "primeng/avatar";
import { Menu } from "primeng/menu";
import { ModalPreferencesComponent } from "../modal-preferences/modal-preferences.component";
import { DialogService, DynamicDialogRef } from "primeng/dynamicdialog";
@Component({
  selector: "coinz-navbar",
  templateUrl: "./navbar.component.html",
  styleUrl: "./navbar.component.scss",
  standalone: true,
  imports: [LogoComponent, DatePicker, FormsModule, Avatar, Menu],
})
export class NavbarComponent implements OnInit {
  protected items_menu: MenuItem[] | undefined;

  protected userInitials: string | undefined;
  protected month_selected: WritableSignal<Date> = signal(new Date());
  protected isShowDatePicker$: Observable<boolean> | undefined;
  protected isModalPreferencesVisible: WritableSignal<boolean> = signal(false);

  private _ref: DynamicDialogRef | undefined;

  #_dialogService = inject(DialogService);
  #_datePickerService = inject(DatePickerService);
  #_storageService = inject(StorageService);

  ngOnInit(): void {
    this.userInitials = CoreUtil.getUserNameInitials(this.#_storageService);
    this.#_datePickerService.datePickerObservable$.subscribe({
      next: data => this.month_selected.set(data),
    });

    this.items_menu = [
      {
        label: "Preferências",
        icon: "pi pi-cog",
        command: () => this._openModalPreferences(),
      },
      {
        separator: true,
      },
      {
        label: "Sair",
        icon: "pi pi-power-off",
        command: () => this.#_storageService.clearAndRefreshPage(),
      },
    ];
  }

  protected onDateChange(date: Date): void {
    this.#_datePickerService.notifyDateChanges(date);
  }

  // Metódo responsavel por abrir modal de preferencias
  private _openModalPreferences(): void {
    this._ref = this.#_dialogService.open(ModalPreferencesComponent, {
      modal: true,
      header: "Preferências usuário",
      closable: true,
      contentStyle: { overflow: "auto" },
    });
  }
}
