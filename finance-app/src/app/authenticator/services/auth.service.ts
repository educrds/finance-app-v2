import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Usuario } from '../../interfaces/Usuario';
import { AuthResponse, IAuthService } from '../../interfaces/IAuthService';
@Injectable({
  providedIn: 'root',
})
export class AuthService implements IAuthService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) {}

  public authenticateUser(form: Usuario, isSocialAuth?: boolean): Observable<AuthResponse> {
    return this._http.post<AuthResponse>(`${this._api_url}user/login`, { 
      data: form,
      socialAuth: isSocialAuth ?? false
    });
  }

  public registerUser(form: Usuario, isSocialAuth?: boolean): Observable<AuthResponse> {
    return this._http.post<AuthResponse>(`${this._api_url}user/register`, { 
      data: form,
      socialAuth: isSocialAuth ?? false
    });
  }
}
