import { Observable } from "rxjs";
import { Usuario } from "../models/Usuario";

export type AuthResponse = {
  message: string;
  token: string;
};

export interface IAuthService {
  autenticateUser$(form: Usuario, context: "login" | "register", isSocialAuth?: boolean): Observable<AuthResponse>;
}
