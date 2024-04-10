import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpClient } from '@angular/common/http';
import { Observable, retry } from 'rxjs';
import { IUsuario } from '../../interfaces/IUsuario';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  authenticateUser(form: IUsuario): Observable<any> {
    return this._http
      .post(`${this._api_url}user/login`, { data: form })
      .pipe(retry(1));
  }

  registerUser(form: IUsuario): Observable<any> {
    return this._http
      .post(`${this._api_url}user/register`, { data: form })
      .pipe(retry(1));
  }

}
