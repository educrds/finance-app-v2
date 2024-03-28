import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { retry } from 'rxjs';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})

export class TransacoesService {
  private _api_url = environment.api_url;

  constructor(private _http: HttpClient) { }

  getTransacoes(){
    return this._http.post(`${this._api_url}transacoes/listar`, {
      teste: 'teste'
    }).pipe(retry(1));
  }
}