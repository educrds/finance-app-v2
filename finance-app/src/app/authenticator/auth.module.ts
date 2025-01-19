import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LoginComponent } from './pages/login/login.component';
import { SharedModule } from '../shared/shared.module';
import { ReactiveFormsModule } from '@angular/forms';

import { InputTextModule } from 'primeng/inputtext';
import { ButtonModule } from 'primeng/button';
import { PasswordModule } from 'primeng/password';
import { RegisterComponent } from './pages/register/register.component';
import { DividerModule } from 'primeng/divider';
import { SocialButtonsComponent } from './components/social-buttons/social-buttons.component';
import { AuthRoutingModule } from './auth-routing.module';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';
@NgModule({
    imports: [CommonModule,
        AuthRoutingModule,
        InputTextModule,
        ReactiveFormsModule,
        ButtonModule,
        SharedModule,
        PasswordModule,
        DividerModule, LoginComponent,
        RegisterComponent,
        SocialButtonsComponent], providers: [provideHttpClient(withInterceptorsFromDi())] })
export class AuthModule { }
