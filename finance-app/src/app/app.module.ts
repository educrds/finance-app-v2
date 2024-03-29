import { NgModule } from '@angular/core';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { HttpClientModule } from '@angular/common/http';
import { HomeComponent } from './pages/home/home.component';
import { NavbarComponent } from './components/navbar/navbar.component';
import { SidebarComponent } from './components/sidebar/sidebar.component';

import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

import { MenuModule } from 'primeng/menu';
import { ToastModule } from 'primeng/toast';
import { BrowserModule } from '@angular/platform-browser';
import { SplitButtonModule } from 'primeng/splitbutton';
import { WrapContainerComponent } from './shared/components/wrap-container/wrap-container.component';
import { AvatarModule } from 'primeng/avatar';
import { AvatarGroupModule } from 'primeng/avatargroup';
import { CalendarModule } from 'primeng/calendar';
import { ReactiveFormsModule } from '@angular/forms';
import { LogoComponent } from './shared/components/logo/logo.component';
import { MainComponent } from './components/main/main.component';
import { ColumnComponent } from './shared/components/column/column.component';
import { RowComponent } from './shared/components/row/row.component';
import { TableModule } from 'primeng/table';
import { ChipModule } from 'primeng/chip';
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
    RowComponent
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
    AvatarModule,
    AvatarGroupModule,
    TableModule,
    ChipModule,
    CalendarModule,
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
