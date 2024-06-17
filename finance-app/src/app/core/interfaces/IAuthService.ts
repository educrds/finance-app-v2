import { Observable } from "rxjs";
import { Usuario } from "../models/Usuario";

export type AuthResponse = {
  message: string;
  token: string;
};

export interface IAuthService {
  loginUser$(form: Usuario, isSocialAuth?: boolean): Observable<AuthResponse>;
  registerUser$(form: Usuario, isSocialAuth?: boolean): Observable<AuthResponse>;
}
