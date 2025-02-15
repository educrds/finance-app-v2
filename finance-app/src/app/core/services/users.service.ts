import { HttpClient } from "@angular/common/http";
import { Injectable, inject } from "@angular/core";
import { Observable, shareReplay } from "rxjs";
import { environment } from "../../../environments/environment";
import { Users } from "../models/User";

@Injectable({
  providedIn: 'root',
})
export class UsersService {
  #_api_url = environment.api_url;
  #_http = inject(HttpClient)

  /**
   * Obtém uma lista de usuários.
   * @returns Um Observable contendo uma lista de usuários.
   */
  getUsersList$(): Observable<Users[]> {
    return this.#_http
      .post<Users[]>(`${this.#_api_url}user/list-users`, {
        data: {},
      })
      .pipe(shareReplay(1));
  }
}
