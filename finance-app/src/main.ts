import { MessageService, ConfirmationService } from 'primeng/api';
import { DialogService } from 'primeng/dynamicdialog';
import { httpInterceptorProvider } from './app/helpers/http-interceptor.interceptor';
import { provideHttpClient, withFetch, withInterceptorsFromDi } from '@angular/common/http';
import { provideAnimations } from '@angular/platform-browser/animations';
import { BrowserModule, bootstrapApplication } from '@angular/platform-browser';
import { RouterModule } from '@angular/router';
import { AppRoutingModule } from './app/app-routing.module';
import { ToastModule } from 'primeng/toast';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { AuthModule } from '@auth0/auth0-angular';
import { environment } from './environments/environment';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { AppComponent } from './app/app.component';
import { importProvidersFrom } from '@angular/core';


bootstrapApplication(AppComponent, {
    providers: [
        importProvidersFrom(BrowserModule, RouterModule, AppRoutingModule, ToastModule, ConfirmDialogModule, AuthModule.forRoot({
            domain: environment.auth0.domain,
            clientId: environment.auth0.clientId,
        }), FontAwesomeModule),
        MessageService,
        ConfirmationService,
        DialogService,
        httpInterceptorProvider,
        provideHttpClient(withFetch(), withInterceptorsFromDi()),
        provideAnimations()
    ]
})
  .catch(err => console.error(err));
