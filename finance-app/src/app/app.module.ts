import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';

// modules
import { BrowserModule } from '@angular/platform-browser';
import { AuthModule } from './authenticator/auth.module';
import { SharedModule } from './shared/shared.module';
import { AppRoutingModule } from './app-routing.module';
import { HttpClientModule } from '@angular/common/http';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

// components
import { HomeComponent } from './pages/home/home.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { MainComponent } from './components/main/main.component';
import { ReceitasComponent } from './components/receitas/receitas.component';
import { DespesasComponent } from './components/despesas/despesas.component';
import { ModalTransacaoComponent } from './templates/modal-transacao/modal-transacao.component';
import { CategoriasComponent } from './components/categorias/categorias.component';
import { ModalCategoriaComponent } from './templates/modal-categoria/modal-categoria.component';
import { httpInterceptorProvider } from './helpers/http-interceptor.interceptor';


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
import { MenubarModule } from 'primeng/menubar';
import { ChartModule } from 'primeng/chart';



@NgModule({
  declarations: [
    AppComponent,
    HomeComponent,
    NavbarComponent,
    SidebarComponent,
    MainComponent,
    ReceitasComponent,
    DespesasComponent,
    ModalTransacaoComponent,
    CategoriasComponent,
    ModalCategoriaComponent,
  ],
  imports: [
    SharedModule,
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
    TooltipModule,
    AuthModule,
    MenubarModule,
    ChartModule
  ],
  providers: [
    MessageService,
    ConfirmationService,
    DialogService,
    httpInterceptorProvider,
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}
