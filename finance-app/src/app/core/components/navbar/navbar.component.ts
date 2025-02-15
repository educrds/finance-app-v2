import { Component, OnInit, WritableSignal, inject, signal } from "@angular/core";
import { MenuItem } from "primeng/api";
import { DatePickerService } from "../../services/date-picker.service";
import { NavigationEnd, Router } from "@angular/router";
import { Observable, filter, map, startWith } from "rxjs";
import { StorageService } from "../../services/storage.service";
import CoreUtil from "../../utils";
import { WrapContainerComponent } from "../wrap-container/wrap-container.component";
import { LogoComponent } from "../../../shared/components/logo/logo.component";
import { DatePicker } from "primeng/datepicker";
import { FormsModule } from "@angular/forms";
import { Avatar } from "primeng/avatar";
import { Menu } from "primeng/menu";
import { AsyncPipe } from "@angular/common";
import { ModalPreferencesComponent } from "../modal-preferences/modal-preferences.component";
import { DialogService, DynamicDialogRef } from "primeng/dynamicdialog";
import { SplitButton } from "primeng/splitbutton";
import { ModalTransacaoComponent } from "../../templates/modal-transacao/modal-transacao.component";
@Component({
    selector: "fin-navbar",
    templateUrl: "./navbar.component.html",
    styleUrl: "./navbar.component.scss",
    standalone: true,
    imports: [
    WrapContainerComponent,
    LogoComponent,
    DatePicker,
    FormsModule,
    SplitButton,
    Avatar,
    Menu,
    AsyncPipe
],
})
export class NavbarComponent implements OnInit {
  protected items_menu: MenuItem[] | undefined;
  protected items_transacao: MenuItem[] = [];

  protected userInitials: string | undefined;
  protected month_selected: WritableSignal<Date> = signal(new Date());
  protected isShowDatePicker$: Observable<boolean> | undefined;
  protected isModalPreferencesVisible: WritableSignal<boolean> = signal(false);

  #navigationEvents$: Observable<NavigationEnd> | undefined;
  private _ref: DynamicDialogRef | undefined;

  #_dialogService = inject(DialogService);
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

    this.items_menu = [
      {
        label: "Preferências",
        icon: "pi pi-cog",
        command: () => this._openModalPreferences(),
      },
      {
        separator: true
      },
      {
        label: "Sair",
        icon: "pi pi-power-off",
        command: () => this.#_storageService.clearAndRefreshPage(),
      },
    ];
    this.setupItemsMenuTransacao();
  }

  private setupItemsMenuTransacao(): void {
    this.items_transacao = [
      {
        label: "Entradas",
        command: () => this.openModalAdd(1),
      },
      {
        label: "Saídas",
        command: () => this.openModalAdd(2),
      },
    ];
  }

  // Metódo responsavel por abrir modal de preferencias
  private _openModalPreferences(): void {
    this._ref = this.#_dialogService.open(ModalPreferencesComponent, {
      modal: true,
      header: 'Preferências usuário',
      closable: true,
      contentStyle: { overflow: 'auto' },
    });
  }

  private checkRoute(url: string): boolean {
    return !url.includes("/categorias");
  }

  protected onDateChange(date: Date): void {
    this.#_datePickerService.notifyDateChanges(date);
  }

  protected openModalAdd(trs_tipo: number) {
    const header = trs_tipo === 1 ? "Nova Receita" : "Nova Despesa";

    this._ref = this.#_dialogService.open(ModalTransacaoComponent, {
      modal: true,
      header: header,
      closable: true,
      contentStyle: { overflow: "auto" },
      data: {
        id_tipo_transacao: trs_tipo,
      },
    });
  }
}
