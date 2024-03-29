import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';

@Component({
  selector: 'fin-navbar',
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.scss',
})
export class NavbarComponent implements OnInit {
  protected monthInputForm!: FormGroup;

  constructor(private _fb: FormBuilder) {}

  ngOnInit(): void {
    this.monthInputForm = new FormGroup({
      month_selected: this._fb.control(this.getCurrentMonthFormatted()),
    });
  }

  private getCurrentMonthFormatted() {
    const date = new Date();
    const year = date.getFullYear();
    const month = date.getMonth() + 1;

    const current_month = new Date(`${year}, ${month}, 01`);

    return current_month;
  }
}
