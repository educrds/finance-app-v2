import { HttpClient } from "@angular/common/http";
import { inject, Injectable } from "@angular/core";
import { environment } from "../../../environments/environment";
import { Observable, shareReplay } from "rxjs";
import { Preference } from "../models/Preference";

@Injectable({
  providedIn: "root",
})
export class PreferencesService {
  #_api_url = environment.api_url;
  #_http = inject(HttpClient);

  /**
   * Obtém lista de preferencias do usuario.
   * @returns Um Observable contendo um objeto de preferencias.
   */
  getPreferences$(): Observable<Preference> {
    return this.#_http
      .post<Preference>(`${this.#_api_url}preferencias/listar-preferencias`, {})
      .pipe(shareReplay(1));
  }

  /**
   * Atualiza lista de preferencias do usuario.
   * @returns mensagem de sucesso ou erro.
   */
  updatePreferencesByUser$(preferences: Preference): Observable<{"message": string}> {
    return this.#_http
      .post<{"message": string}>(`${this.#_api_url}preferencias/atualizar-preferencia`, {
        "data": preferences
      })
      .pipe(shareReplay(1));
  }
}
