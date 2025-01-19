import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { Router } from '@angular/router';
import { StorageService } from '../../../core/services/storage.service';
import { ColumnComponent } from '../../../shared/components/column/column.component';
import { InputTextModule } from 'primeng/inputtext';
import { PasswordModule } from 'primeng/password';
import { Button } from 'primeng/button';
import { SocialButtonsComponent } from '../../components/social-buttons/social-buttons.component';

@Component({
    selector: 'fin-login',
    templateUrl: './login.component.html',
    styleUrl: './login.component.scss',
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
export class LoginComponent implements OnInit {
  protected formAuthenticator: FormGroup = this._fb.group({});

  constructor(
    private _fb: FormBuilder,
    private _authService: AuthService,
    protected _router: Router,
    private _storageService: StorageService,
  ) {}

  ngOnInit(): void {
    this.formAuthenticator = this._fb.group({
      auth_email: ['', Validators.compose([Validators.required, Validators.email])],
      auth_password: ['', Validators.compose([Validators.required, Validators.minLength(8)])],
    });
  }

  autenticarUsuario() {
    if (this.formAuthenticator.valid) {
      const form = this.formAuthenticator.getRawValue();
      this._authService.loginUser$(form).subscribe({
        next: (res) => {
          this._storageService.saveUser(res.token);
          this._router.navigate(['/']);
        },
        error: (err) => console.error(err),
      });
    }
  }
}
