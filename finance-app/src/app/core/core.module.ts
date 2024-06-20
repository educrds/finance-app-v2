import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { CoreRoutingModule } from './core-routing.module';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';
import { AccordionModule } from 'primeng/accordion';
import { AvatarModule } from 'primeng/avatar';
import { AvatarGroupModule } from 'primeng/avatargroup';
import { CalendarModule } from 'primeng/calendar';
import { ChipModule } from 'primeng/chip';
import { ColorPickerModule } from 'primeng/colorpicker';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { DialogModule } from 'primeng/dialog';
import { DropdownModule } from 'primeng/dropdown';
import { DynamicDialogModule } from 'primeng/dynamicdialog';
import { InputNumberModule } from 'primeng/inputnumber';
import { InputSwitchModule } from 'primeng/inputswitch';
import { InputTextModule } from 'primeng/inputtext';
import { MenuModule } from 'primeng/menu';
import { MenubarModule } from 'primeng/menubar';
import { MessagesModule } from 'primeng/messages';
import { SplitButtonModule } from 'primeng/splitbutton';
import { TableModule } from 'primeng/table';
import { ToastModule } from 'primeng/toast';
import { TooltipModule } from 'primeng/tooltip';
import { HomeComponent } from './pages/home/home.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { CategoriasComponent } from './components/categorias/categorias.component';
import { DespesasComponent } from './components/despesas/despesas.component';
import { ReceitasComponent } from './components/receitas/receitas.component';
import { MainComponent } from './components/main/main.component';
import { ModalCategoriaComponent } from './templates/modal-categoria/modal-categoria.component';
import { ModalTransacaoComponent } from './templates/modal-transacao/modal-transacao.component';
import { SharedModule } from '../shared/shared.module';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';

@NgModule({
  declarations: [
    HomeComponent,
    NavbarComponent,
    SidebarComponent,
    CategoriasComponent,
    DespesasComponent,
    ReceitasComponent,
    MainComponent,
    ModalCategoriaComponent,
    ModalTransacaoComponent,
  ],
  imports: [
    CommonModule,
    CoreRoutingModule,
    MenuModule,
    ReactiveFormsModule,
    ToastModule,
    SplitButtonModule,
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
    MenubarModule,
    AccordionModule,
    FormsModule,
    SharedModule,
    FontAwesomeModule
  ],
  exports: [CoreRoutingModule]
})
export class CoreModule { }
