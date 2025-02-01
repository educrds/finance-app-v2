import { inject, Injectable } from "@angular/core";
import { FormGroup, FormBuilder, Validators } from "@angular/forms";
import { Router } from "@angular/router";
import { tap } from "rxjs";
import { StorageService } from "../../../core/services/storage.service";
import { AuthService } from "../../services/auth.service";
import { MessagesService } from "../../../core/services/messages.service";

@Injectable()
export abstract class AuthComponentBase {
  protected formAuthenticator!: FormGroup;

  protected router = inject(Router);
  private _fb = inject(FormBuilder);
  private _authService = inject(AuthService);
  private _storageService = inject(StorageService);
  private _messagesService = inject(MessagesService);

  protected abstract get authType(): "register" | "login";

  constructor() {
    this.formAuthenticator = this._fb.group(this.getFormSetup());
  }

  private getFormSetup() {
    const config = {
      auth_email: ["", [Validators.required, Validators.email]],
      auth_password: ["", [Validators.required, Validators.minLength(8)]],
    };

    if (this.authType === "register") {
      return {
        auth_name: ["", [Validators.required, Validators.pattern("[a-zA-Z]+")]],
        ...config,
      };
    }

    return config;
  }

  protected redirectPage(): void {
    const pathToRedirect = this.authType === 'register' ? 'login' : 'register';
    this.router.navigate([`/auth/${pathToRedirect}`]);
  }

  protected autenticarUsuario(): void {
    if (this.formAuthenticator.valid) {
      const form = this.formAuthenticator.getRawValue();
      this._authService
        .autenticateUser$(form, this.authType)
        .pipe(
          tap(res => this._storageService.saveUser(res.token)),
          tap(() => this.router.navigate(["/"]))
        )
        .subscribe({
          error: ({ message }) => this._messagesService.showError(message)
        });
    }
  }
}
