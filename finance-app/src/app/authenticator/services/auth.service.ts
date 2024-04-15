import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { IUsuario } from '../../interfaces/IUsuario';
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient, private _router: Router) {}

  authenticateUser(form: IUsuario): Observable<any> {
    return this._http.post(`${this._api_url}user/login`, { data: form })
  }

  registerUser(form: IUsuario): Observable<any> {
    return this._http.post(`${this._api_url}user/register`, { data: form })
  }

  handleHttpError(error: HttpErrorResponse) {
    // return catchError((error: HttpErrorResponse) => {
      if (error.status === 401) {
        // Se a resposta for 401 Unauthorized, redirecione para a rota /login
        this._router.navigate(['/login']);
      } else if (error.status === 404) {
        // Trate o erro 404 (Not Found) de acordo com os requisitos da sua aplicação
        console.error('Recurso não encontrado. Status: 404');
      } else if (error.status === 500) {
        // Trate o erro 500 (Internal Server Error) de acordo com os requisitos da sua aplicação
        console.error('Erro interno do servidor. Status: 500');
      } else {
        // Trate outros erros de acordo com os requisitos da sua aplicação
        console.error('Erro não tratado. Status:', error.status);
      }
      return throwError(error);
    // });
  }
}
