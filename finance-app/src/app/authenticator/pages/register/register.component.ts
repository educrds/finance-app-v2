import { Component, ElementRef, afterRender } from '@angular/core';
import { FormGroup, FormBuilder, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { StorageService } from '../../../shared/services/storage.service';

@Component({
  selector: 'fin-register',
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss',
})
export class RegisterComponent {
  formAuthenticator!: FormGroup;

  constructor(
    private _fb: FormBuilder,
    private _authService: AuthService,
    private _router: Router,
    private _storageService: StorageService
  ) {}

  ngOnInit(): void {
    this.formAuthenticator = this._fb.group({
      auth_name: [
        '',
        Validators.compose([
          Validators.required,
          Validators.pattern('[a-zA-Z]+'),
        ]),
      ],
      auth_email: [
        '',
        Validators.compose([Validators.required, Validators.email]),
      ],
      auth_password: [
        '',
        Validators.compose([Validators.required, Validators.minLength(8)]),
      ],
    });
  }

  protected goToLogin(): void {
    this._router.navigate(['/auth/login'])
  }

  autenticarUsuario() {
    if (this.formAuthenticator.valid) {
      const form = this.formAuthenticator.getRawValue();
      this._authService.registerUser$(form).subscribe({
        next: (res) => {
          this._storageService.saveUser(res.token);
          this._router.navigate(['/']);
        },
        error: (err) => console.error(err),
      });
    }
  }
}
