import { Component, inject, input } from "@angular/core";
import { StorageService } from "../../../core/services/storage.service";
import { Router } from "@angular/router";
import { AuthService } from "../../services/auth.service";
import { DividerModule } from "primeng/divider";
import { Button } from "primeng/button";
import { filter, switchMap } from "rxjs";
import { Usuario } from "../../../core/models/Usuario";
import { AuthService as Auth0Service, IdToken } from "@auth0/auth0-angular";

@Component({
  selector: "fin-social-buttons",
  templateUrl: "./social-buttons.component.html",
  styleUrl: "./social-buttons.component.scss",
  standalone: true,
  imports: [DividerModule, Button],
})
export class SocialButtonsComponent {
  public context = input<'login' | 'register'>("login");

  private _router = inject(Router);
  private _auth0 = inject(Auth0Service);
  private _authService = inject(AuthService);
  private _storageService = inject(StorageService);

  private _getInfoUserAuthenticated(): void {
    this._auth0.isAuthenticated$
      .pipe(
        filter(isAuthenticated => isAuthenticated),
        switchMap(() => this._auth0.idTokenClaims$)
      )
      .subscribe(userInfos => this.checkContext(userInfos));
  }

  private checkContext(userInfo: IdToken | null | undefined): void {
    const user: Usuario = {
      auth_name: userInfo?.name,
      auth_email: userInfo?.email,
    };

    this._authService.autenticateUser$(user, this.context(), true).subscribe({
      next: ({ token }) => {
        this._storageService.saveUser(token);
        this._router.navigate(["/"]);
      },
    });
  }

  protected authWithGoogle(): void {
    this._auth0
      .loginWithPopup({
        authorizationParams: {
          connection: "google-oauth2",
          prompt: "select_account",
        },
      })
      .subscribe(() => this._getInfoUserAuthenticated());
  }
}
