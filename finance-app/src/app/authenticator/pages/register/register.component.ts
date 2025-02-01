import { Component } from "@angular/core";
import { FormsModule, ReactiveFormsModule } from "@angular/forms";
import { ColumnComponent } from "../../../shared/components/column/column.component";
import { InputTextModule } from "primeng/inputtext";
import { PasswordModule } from "primeng/password";
import { Button } from "primeng/button";
import { SocialButtonsComponent } from "../../components/social-buttons/social-buttons.component";
import { AuthComponentBase } from "../../components/auth-component/auth-component.base";

@Component({
  selector: "fin-register",
  templateUrl: "../../components/auth-component/auth-component.base.html",
  styleUrl: "../../components/auth-component/auth-component.base.scss",
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
export class RegisterComponent extends AuthComponentBase {
  protected override get authType(): "login" | "register" {
    return "register";
  }
}
