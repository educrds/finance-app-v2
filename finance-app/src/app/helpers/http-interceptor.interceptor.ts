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
import { JwtPayload, jwtDecode } from 'jwt-decode';

@Injectable()
export class ApiRequestInterceptor implements HttpInterceptor {
  constructor(
    private _storageService: StorageService,
    private _router: Router
  ) {}

  intercept(req: HttpRequest<any>, next: HttpHandler) {
    if (req.url.includes('/login') || req.url.includes('/register')) {
      return next.handle(req);
    }

    if (this._storageService.isLoggedIn()) {
      const token = this._storageService.getToken;
      const decoded = token && jwtDecode<JwtPayload>(token);

      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
        },
        body: { ...req.body, usr_id: decoded?.sub },
      });

      return next.handle(req).pipe(
        catchError((error: HttpErrorResponse) => {
          if (error.status === 401) {
            // Se a resposta for 401 Unauthorized, redirecione para a rota /all
            this._router.navigate(['/login']);
          }
          return throwError(error);
        })
      );
    } else {
      this._router.navigate(['/login']);
      return throwError('Usuário não autenticado');
    }
  }
}
export const httpInterceptorProvider = {
  provide: HTTP_INTERCEPTORS,
  useClass: ApiRequestInterceptor,
  multi: true,
};
