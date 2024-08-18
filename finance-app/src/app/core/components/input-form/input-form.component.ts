import { ChangeDetectionStrategy, Component, Input, forwardRef } from "@angular/core";
import {
  AbstractControl,
  ControlValueAccessor,
  FormControl,
  NG_VALIDATORS,
  NG_VALUE_ACCESSOR,
  ValidationErrors,
  Validators,
} from "@angular/forms";

@Component({
  selector: "fin-input-form",
  templateUrl: "./input-form.component.html",
  styleUrl: "./input-form.component.scss",
  providers: [
    {
      provide: NG_VALUE_ACCESSOR,
      useExisting: forwardRef(() => InputFormComponent),
      multi: true,
    },
    {
      provide: NG_VALIDATORS,
      useExisting: forwardRef(() => InputFormComponent),
      multi: true,
    },
  ],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class InputFormComponent implements ControlValueAccessor {
  @Input() label?: string = "";
  @Input() placeholder?: string = "";
  @Input() type: string = "text";

  protected control: FormControl = new FormControl("", Validators.required);

  protected onTouched: () => void = () => {};

  /**
   * Writes a new value to the element.
   * @param value - The new value to be written.
   */
  public writeValue(value: any): void {
    this.control.setValue(value, { emitEvent: false });
  }

  /**
   * Registers a callback function that is called when the control's value changes in the UI.
   * @param fn - The callback function to register.
   */
  public registerOnChange(fn: any): void {
    this.control.valueChanges.subscribe(fn);
  }

  /**
   * Registers a callback function that is called by the forms API on initialization to update the form model on blur.
   * @param fn - The callback function to register.
   */
  public registerOnTouched(fn: any): void {
    this.onTouched = fn;
  }

  /**
   * Sets the "disabled" property on the input element.
   * @param isDisabled - The boolean value to set the disabled state.
   */
  public setDisabledState?(isDisabled: boolean): void {
    isDisabled ? this.control.disable() : this.control.enable();
  }

  /**
   * Validates the control.
   * @param control - The control to validate.
   * @returns A validation result, or null if the control is valid.
   */
  public validate(control: AbstractControl): ValidationErrors | null {
    return this.control.valid ? null : { invalidForm: { valid: false, message: "Input is invalid" } };
  }
}
