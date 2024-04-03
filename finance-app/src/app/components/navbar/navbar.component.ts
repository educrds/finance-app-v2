import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { DateFilterService } from '../../services/date-filter.service';

@Component({
  selector: 'fin-navbar',
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.scss',
})
export class NavbarComponent implements OnInit {
  protected filterDateForm!: FormGroup;

  constructor(
    private _fb: FormBuilder,
    private _dateFilterService: DateFilterService
  ) {}

  ngOnInit(): void {
    this.filterDateForm = this._fb.group({
      month_selected: this._fb.control(this.getCurrentMonthFormatted()),
    });

    this.filterDateForm.controls['month_selected'].valueChanges.subscribe(
      (date) => {
        this._dateFilterService.notifyChanges({ date });
      }
    );
  }

  private getCurrentMonthFormatted() {
    const date = new Date();
    const year = date.getFullYear();
    const month = date.getMonth() + 1;

    const current_month = new Date(`${year}, ${month}, 01`);

    return current_month;
  }
}
