import { Observable } from "rxjs";
import { Usuario } from "./Usuario";

export type AuthResponse = {
  message: string;
  token: string;
};

export interface IAuthService {
  authenticateUser(form: Usuario, isSocialAuth?: boolean): Observable<AuthResponse>;
  registerUser(form: Usuario, isSocialAuth?: boolean): Observable<AuthResponse>;
}
