import {
  HTTP_INTERCEPTORS,
  HttpErrorResponse,
  HttpHandler,
  HttpInterceptor,
  HttpRequest,
} from '@angular/common/http';
import { Injectable } from '@angular/core';
import { catchError, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { StorageService } from '../shared/services/storage.service';
import { AuthService } from '../authenticator/services/auth.service';
import { MessagesService } from '../services/messages.service';

@Injectable()
export class ApiRequestInterceptor implements HttpInterceptor {
  constructor(
    private _storageService: StorageService,
    private _router: Router,
    private _messagesService: MessagesService,
    private _authService: AuthService
  ) {}

  intercept(req: HttpRequest<any>, next: HttpHandler) {
    const authRoutes = req.url.includes('/login') || req.url.includes('/register');

    if (authRoutes) {
      return next.handle(req).pipe(
        catchError((err: HttpErrorResponse) => {
          this._messagesService.showError(err.error.message);
          return throwError(err);
        })
      );
    }

    // Verifica usuario logado e segue com a requisiçao enviando payload modificado
    // com headers e id do usuário no body.
    if (this._storageService.isLoggedIn()) {
      const token = this._storageService.getToken;

      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
        },
      });

      return next
        .handle(req)
        .pipe(
          catchError((error: HttpErrorResponse) => this._authService.handleHttpError(error))
        );
    }

    this._router.navigate(['/login']);
    this._messagesService.showError('Usúario não autenticado.');
    return throwError('Usuário não autenticado');
  }
}

export const httpInterceptorProvider = {
  provide: HTTP_INTERCEPTORS,
  useClass: ApiRequestInterceptor,
  multi: true,
};
