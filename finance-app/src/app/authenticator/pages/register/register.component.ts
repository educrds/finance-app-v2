import { Component, inject, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { StorageService } from '../../../core/services/storage.service';
import { ColumnComponent } from '../../../shared/components/column/column.component';
import { InputTextModule } from 'primeng/inputtext';
import { PasswordModule } from 'primeng/password';
import { Button } from 'primeng/button';
import { SocialButtonsComponent } from '../../components/social-buttons/social-buttons.component';

@Component({
    selector: 'fin-register',
    templateUrl: './register.component.html',
    styleUrl: './register.component.scss',
    standalone: true,
    imports: [
        FormsModule,
        ReactiveFormsModule,
        ColumnComponent,
        InputTextModule,
        PasswordModule,
        Button,
        SocialButtonsComponent,
    ],
})
export class RegisterComponent implements OnInit {
  formAuthenticator!: FormGroup;

  private _router = inject(Router);
  private _fb = inject(FormBuilder);
  private _authService = inject(AuthService);
  private _storageService = inject(StorageService);

  ngOnInit(): void {
    this.formAuthenticator = this._fb.group({
      auth_name: ['', Validators.compose([Validators.required, Validators.pattern('[a-zA-Z]+')])],
      auth_email: ['', Validators.compose([Validators.required, Validators.email])],
      auth_password: ['', Validators.compose([Validators.required, Validators.minLength(8)])],
    });
  }

  protected goToLogin(): void {
    this._router.navigate(['/auth/login'])
  }

  autenticarUsuario() {
    if (this.formAuthenticator.valid) {
      const form = this.formAuthenticator.getRawValue();
      this._authService.autenticateUser$(form, 'register').subscribe({
        next: (res) => {
          this._storageService.saveUser(res.token);
          this._router.navigate(['/']);
        },
        error: (err) => console.error(err),
      });
    }
  }
}
