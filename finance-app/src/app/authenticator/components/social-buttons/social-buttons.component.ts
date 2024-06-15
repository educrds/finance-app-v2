import { Component, Input } from '@angular/core';
import { AuthService as Auth0Service } from '@auth0/auth0-angular';
import { StorageService } from '../../../shared/services/storage.service';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'fin-social-buttons',
  templateUrl: './social-buttons.component.html',
  styleUrl: './social-buttons.component.scss',
})
export class SocialButtonsComponent {
  @Input() context: string = 'login';

  constructor(
    private _auth0: Auth0Service,
    private _storageService: StorageService,
    private _authService: AuthService,
    private _router: Router
  ) {}

  private _getInfoUserAuthenticated(): void {
    this._auth0.isAuthenticated$.subscribe((isAuthenticated) => {
      if (isAuthenticated) {
        this._auth0.idTokenClaims$.subscribe((userInfos) => this.checkContext(userInfos));
      }
    });
  }

  private checkContext(userInfo: any) {
    const { name, email, __raw: token } = userInfo;

    const user = {
      auth_name: name,
      auth_email: email,
    };

    const serviceToUse = this.context === 'register'
        ? this._authService.registerUser(user, true)
        : this._authService.authenticateUser(user, true);

    serviceToUse.subscribe({
      next: () => {
        this._storageService.saveUser(token);
        this._router.navigate(['/']);
      },
    });
  }

  protected authWithGoogle(): void {
    this._auth0.loginWithPopup({
      authorizationParams: {
        connection: 'google-oauth2',
      },
    });
    this._getInfoUserAuthenticated();
  }
}