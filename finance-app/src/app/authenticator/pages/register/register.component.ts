import { Component } from '@angular/core';
import { FormGroup, FormBuilder, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'fin-register',
  templateUrl: './register.component.html',
  styleUrl: './register.component.scss'
})
export class RegisterComponent {
  formAuthenticator!: FormGroup;

  constructor(
    private _fb: FormBuilder,
    private _authService: AuthService,
    private _router: Router
  ) {}

  ngOnInit(): void {
    this.formAuthenticator = this._fb.group({
      auth_name: ['Eduardo Cardoso', Validators.required],
      auth_email: [
        'edu@gmail.com',
        Validators.compose([Validators.required, Validators.email]),
      ],
      auth_password: ['Capivara@1010', Validators.required],
    });
  }

  autenticarUsuario() {
    if (this.formAuthenticator.valid) {
      const form = this.formAuthenticator.getRawValue();
      this._authService.registerUser(form).subscribe({
        next: (res) => {
          localStorage.setItem('token', res.token);
          this._router.navigate(['/']);
        },
        error: (err) => console.error(err),
      });
    }
  }
}
