import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Usuario } from '../../interfaces/Usuario';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  authenticateUser(form: Usuario): Observable<any> {
    return this._http.post(`${this._api_url}user/login`, { data: form })
  }

  registerUser(form: Usuario): Observable<any> {
    return this._http.post(`${this._api_url}user/register`, { data: form })
  }
}