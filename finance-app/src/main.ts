import { MessageService, ConfirmationService } from "primeng/api";
import { DialogService } from "primeng/dynamicdialog";
import { httpInterceptorProvider } from "./app/helpers/http-interceptor.interceptor";
import { provideHttpClient, withFetch, withInterceptorsFromDi } from "@angular/common/http";
import { provideAnimations } from "@angular/platform-browser/animations";
import { BrowserModule, bootstrapApplication } from "@angular/platform-browser";
import { provideRouter, RouterModule } from "@angular/router";
import { APP_ROUTES } from "./app/app-routes";
import { ToastModule } from "primeng/toast";
import { ConfirmDialogModule } from "primeng/confirmdialog";
import { AuthModule } from "@auth0/auth0-angular";
import { environment } from "./environments/environment";
import { FontAwesomeModule } from "@fortawesome/angular-fontawesome";
import { AppComponent } from "./app/app.component";
import { importProvidersFrom, InjectionToken } from "@angular/core";
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { providePrimeNG } from "primeng/config";
import Lara from '@primeng/themes/lara';
import { PreferencesService } from "./app/core/services/preferences.service";

export const PREFERENCES_TOKEN = new InjectionToken('PREFERENCES_TOKEN');

export const preferencesProvider = {
  provide: PREFERENCES_TOKEN,
  useFactory: (preferencesService: PreferencesService) => preferencesService.getPreferences$(),
  deps: [PreferencesService],
};

bootstrapApplication(AppComponent, {
  providers: [
    provideAnimationsAsync(),
    providePrimeNG({ 
        theme: {
            preset: Lara
        }
    }),
    preferencesProvider,
    importProvidersFrom(
      BrowserModule,
      RouterModule,
      ToastModule,
      ConfirmDialogModule,
      AuthModule.forRoot({
        domain: environment.auth0.domain,
        clientId: environment.auth0.clientId,
      }),
      FontAwesomeModule
    ),
    provideRouter(APP_ROUTES),
    MessageService,
    ConfirmationService,
    DialogService,
    httpInterceptorProvider,
    provideHttpClient(withFetch(), withInterceptorsFromDi()),
    provideAnimations(),
  ],
}).catch(err => console.error(err));
