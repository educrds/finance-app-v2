import { TestBed } from "@angular/core/testing";
import { DatePickerService } from "./date-picker.service";

describe(DatePickerService.name , () => {
  let service: DatePickerService;
  
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [DatePickerService]
    })

    service = TestBed.inject(DatePickerService);
  })
  
  it(`✅datePickerObservable$ deve retornar corretamente a data inicial.`, () => {
    const expectedDate: Date = service.getCurrentMonthFormatted();

    service.datePickerObservable$.subscribe(response => expect(response).toEqual(expectedDate))
  })
  
  it(`✅datePickerObservable$ deve retornar corretamente a data armazenada.`, () => {
    const expectedDate: Date = new Date(2024, 11, 1);
    service.notifyDateChanges(expectedDate);

    service.datePickerObservable$.subscribe(response => expect(response).toEqual(expectedDate));
  })
})