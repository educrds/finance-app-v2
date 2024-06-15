import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LoginComponent } from './pages/login/login.component';
import { SharedModule } from '../shared/shared.module';
import { ReactiveFormsModule } from '@angular/forms';

import { InputTextModule } from 'primeng/inputtext';
import { ButtonModule } from 'primeng/button';
import { PasswordModule } from 'primeng/password';
import { HttpClientModule } from '@angular/common/http';
import { RegisterComponent } from './pages/register/register.component';
import { DividerModule } from 'primeng/divider';
import { SocialButtonsComponent } from './components/social-buttons/social-buttons.component';
import { provideAuth0 } from '@auth0/auth0-angular';
import { environment } from '../../environments/environment';
import { AuthRoutingModule } from './auth-routing.module';
@NgModule({
  declarations: [
    LoginComponent,
    RegisterComponent,
    SocialButtonsComponent
  ],
  imports: [
    CommonModule,
    SharedModule,
    InputTextModule,
    ReactiveFormsModule,
    ButtonModule,
    PasswordModule,
    HttpClientModule,
    DividerModule
  ],
  exports: [AuthRoutingModule],
  providers:[
    provideAuth0(environment.auth0)
  ]
})
export class AuthModule { }
