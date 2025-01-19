import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';

// modules
import { BrowserModule } from '@angular/platform-browser';
import { provideHttpClient, withFetch, withInterceptorsFromDi } from '@angular/common/http';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

// components
import { httpInterceptorProvider } from './helpers/http-interceptor.interceptor';

// primeng
import { DialogService } from 'primeng/dynamicdialog';
import { ConfirmationService, MessageService } from 'primeng/api';
import { RouterModule } from '@angular/router';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { AppRoutingModule } from './app-routing.module';
import { AuthModule } from '@auth0/auth0-angular';
import { environment } from '../environments/environment';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
@NgModule({ declarations: [
        AppComponent
    ],
    bootstrap: [AppComponent], imports: [BrowserAnimationsModule,
        BrowserModule,
        RouterModule,
        AppRoutingModule,
        ToastModule,
        ConfirmDialogModule,
        AuthModule.forRoot({
            domain: environment.auth0.domain,
            clientId: environment.auth0.clientId,
        }),
        FontAwesomeModule], providers: [
        MessageService,
        ConfirmationService,
        DialogService,
        httpInterceptorProvider,
        provideHttpClient(withFetch(), withInterceptorsFromDi()),
    ] })
export class AppModule {}
