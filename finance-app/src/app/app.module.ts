import { NgModule } from '@angular/core';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { HttpClientModule } from '@angular/common/http';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { BrowserModule } from '@angular/platform-browser';

// components
import { HomeComponent } from './pages/home/home.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { WrapContainerComponent } from './shared/components/wrap-container/wrap-container.component';
import { LogoComponent } from './shared/components/logo/logo.component';
import { MainComponent } from './components/main/main.component';
import { ColumnComponent } from './shared/components/column/column.component';
import { RowComponent } from './shared/components/row/row.component';
import { ReceitasComponent } from './components/receitas/receitas.component';
import { DespesasComponent } from './components/despesas/despesas.component';
import { ModalTransacaoComponent } from './templates/modal-transacao/modal-transacao.component';
import { CategoriasComponent } from './components/categorias/categorias.component';
import { ModalCategoriaComponent } from './templates/modal-categoria/modal-categoria.component';
import { TopCardComponent } from './shared/components/top-card/top-card.component';
import { AlertContainerComponent } from './shared/components/alert-container/alert-container.component';

// primeng
import { MenuModule } from 'primeng/menu';
import { ToastModule } from 'primeng/toast';
import { SplitButtonModule } from 'primeng/splitbutton';
import { AvatarModule } from 'primeng/avatar';
import { AvatarGroupModule } from 'primeng/avatargroup';
import { CalendarModule } from 'primeng/calendar';
import { ReactiveFormsModule } from '@angular/forms';
import { TableModule } from 'primeng/table';
import { DialogModule } from 'primeng/dialog';
import { DialogService, DynamicDialogModule } from 'primeng/dynamicdialog';
import { InputTextModule } from 'primeng/inputtext';
import { InputNumberModule } from 'primeng/inputnumber';
import { ConfirmationService, MessageService } from 'primeng/api';
import { DropdownModule } from 'primeng/dropdown';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { ColorPickerModule } from 'primeng/colorpicker';
import { MessagesModule } from 'primeng/messages';
import { InputSwitchModule } from 'primeng/inputswitch';
import { ChipModule } from 'primeng/chip';
import { TooltipModule } from 'primeng/tooltip';

@NgModule({
  declarations: [
    AppComponent,
    HomeComponent,
    NavbarComponent,
    SidebarComponent,
    WrapContainerComponent,
    LogoComponent,
    MainComponent,
    ColumnComponent,
    RowComponent,
    ReceitasComponent,
    DespesasComponent,
    ModalTransacaoComponent,
    CategoriasComponent,
    ModalCategoriaComponent,
    TopCardComponent,
    AlertContainerComponent,
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    MenuModule,
    ReactiveFormsModule,
    ToastModule,
    SplitButtonModule,
    BrowserAnimationsModule,
    DialogModule,
    DynamicDialogModule,
    AvatarModule,
    AvatarGroupModule,
    TableModule,
    InputTextModule,
    InputNumberModule,
    CalendarModule,
    DropdownModule,
    ConfirmDialogModule,
    ColorPickerModule,
    MessagesModule,
    InputSwitchModule,
    ChipModule,
    TooltipModule
  ],
  providers: [MessageService, ConfirmationService, DialogService],
  bootstrap: [AppComponent],
})
export class AppModule {}
