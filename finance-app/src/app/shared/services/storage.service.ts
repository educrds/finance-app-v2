import { Injectable } from '@angular/core';
import { User } from '../../core/interfaces/User';
import { jwtDecode } from 'jwt-decode';

interface JwtPayload {
  name: string,
  email: string
}

@Injectable({
  providedIn: 'root',
})
export class StorageService {
  public saveUser(token: string): void {
    this.clean();
    window.localStorage.setItem('token', token);
  }

  get getToken() {
    return localStorage.getItem('token');
  }

  clean(): void {
    localStorage.removeItem('token');
  }

  clearAndRefreshPage(): void {
    this.clean();
    window.location.reload();
  }

  getUser(): User | null {
    const token = this.getToken;
    if (token) {
      const decodedToken = jwtDecode<JwtPayload>(token);
      const user: User = {
        name: decodedToken.name, // Assumindo que o token tenha a propriedade 'name'
        email: decodedToken.email, // Assumindo que o token tenha a propriedade 'name'
      };
      return user;
    }
    return null;
  }

  private isTokenExpired(): boolean {
    const token = this.getToken;

    if (!token) {
      return true; // Se não houver token, considera-se como expirado
    }

    const tokenPayload = JSON.parse(atob(token.split('.')[1]));
    const expiry = tokenPayload.exp * 1000; // Converte o tempo de expiração para milissegundos

    return expiry <= Date.now(); // Retorna true se o token estiver expirado
  }

  isLoggedIn(): boolean {
    return !this.isTokenExpired();
  }
}
