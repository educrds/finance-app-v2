import { Component, Inject, inject, OnInit } from "@angular/core";
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule } from "@angular/forms";
import { ButtonModule } from "primeng/button";
import { InputTextModule } from "primeng/inputtext";
import { ToggleSwitch } from "primeng/toggleswitch";
import { PreferencesService } from "../../services/preferences.service";
import { DynamicDialogRef } from "primeng/dynamicdialog";
import { MessagesService } from "../../services/messages.service";
import { NotificationService } from "../../services/notification.service";
import { Observable } from "rxjs";
import { PREFERENCES_TOKEN } from "../../../../main";
import { Preference } from "../../models/Preference";

@Component({
  selector: "fin-modal-preferences",
  standalone: true,
  imports: [ButtonModule, InputTextModule, ToggleSwitch, FormsModule, ReactiveFormsModule],
  templateUrl: "./modal-preferences.component.html",
  styleUrl: "./modal-preferences.component.scss",
})
export class ModalPreferencesComponent implements OnInit {
  protected formPreferences: FormGroup;

  private _ref = inject(DynamicDialogRef);
  private _fb = inject(FormBuilder);
  private _preferencesService = inject(PreferencesService);
  private _messagesService = inject(MessagesService);
  private _notificationService = inject(NotificationService);

  constructor(@Inject(PREFERENCES_TOKEN) public chartsPreference$: Observable<Preference>){
    this.formPreferences = this._fb.group({
      preference_id: [null],
      saidas_por_categoria: [false],
      entradas_por_categoria: [false],
      saidas_por_metodo: [false],
      comparativo_mensal: [false],
    });
  }

  ngOnInit(): void {
    this.chartsPreference$.subscribe({
      next: ({ saidas_por_categoria, entradas_por_categoria, saidas_por_metodo, comparativo_mensal, prf_id }) => {
        this.formPreferences = this._fb.group({
          prf_id: [prf_id || null],
          saidas_por_categoria: [Boolean(saidas_por_categoria)],
          entradas_por_categoria: [Boolean(entradas_por_categoria)],
          saidas_por_metodo: [Boolean(saidas_por_metodo)],
          comparativo_mensal: [Boolean(comparativo_mensal)],
        });
      }
    });
  }
  
  protected updatePreference() {
    const form = this.formPreferences.getRawValue();
    this._preferencesService.updatePreferencesByUser$(form).subscribe({
      next: () => {
        this._messagesService.showSuccess("Preferência atualizada com sucesso!");
        this._ref.close();
        this._notificationService.notifyChanges({ refresh: true });
      },
    });
  }
}
