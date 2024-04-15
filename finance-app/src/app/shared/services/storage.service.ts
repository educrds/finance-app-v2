import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root',
})
export class StorageService {
  constructor() {}

  clean(): void {
    localStorage.removeItem('token');
  }
  
  clearAndRefreshPage(): void {
    this.clean();
    window.location.reload();
  }

  public saveUser(token: string): void {
    this.clean();
    window.localStorage.setItem('token', token);
  }

  get getToken() {
    return localStorage.getItem('token');
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
