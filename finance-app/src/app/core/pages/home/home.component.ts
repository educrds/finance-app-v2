import { Component, inject, OnInit, signal, WritableSignal } from "@angular/core";
import { ColumnComponent } from "../../../shared/components/column/column.component";
import { NavbarComponent } from "../../components/navbar/navbar.component";
import { RowComponent } from "../../../shared/components/row/row.component";
import { Router, RouterOutlet } from "@angular/router";
import { TabsModule } from "primeng/tabs";
import { CategoriasComponent } from "../../components/categorias/categorias.component";
import { StorageService } from "../../services/storage.service";

@Component({
  selector: "fin-home",
  templateUrl: "./home.component.html",
  styleUrl: "./home.component.scss",
  standalone: true,
  imports: [ColumnComponent, NavbarComponent, RowComponent, RouterOutlet, TabsModule, CategoriasComponent],
})
export class HomeComponent implements OnInit {
  protected tabs: { [key: string]: string }[] = [];

  public activeTab: WritableSignal<string | number> = signal("");

  private _router = inject(Router);
  private _storageService = inject(StorageService);

  ngOnInit(): void {
    this.createTabs();
    this.verifyUserIsAdmin();
    this.activeTab.set(this._router.url);
  }

  protected verifyUserIsAdmin(): void  {
    const user = this._storageService.getUser();
    if(user?.admin){
      this.tabs.push({
        route: "/users", icon: "pi pi-users", label: "Usuários"
      })
    }
  }

  protected createTabs(): void {
    this.tabs = [
      { route: "/dashboard", icon: "pi pi-chart-bar", label: "Dashboard" },
      { route: "/entradas", icon: "pi pi-arrow-up-right", label: "Entradas" },
      { route: "/saidas", icon: "pi pi-arrow-down-left", label: "Saídas" },
    ];
  }

  protected onTabChange(route: string | number) {
    this.activeTab.set(route);
    this._router.navigateByUrl(String(route));
  }
}
