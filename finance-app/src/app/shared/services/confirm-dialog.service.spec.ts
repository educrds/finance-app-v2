import { ConfirmDialogService } from "./confirm-dialog.service"
import { TestBed } from '@angular/core/testing';

describe(ConfirmDialogService.name, () => {
  let service: ConfirmDialogService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [ConfirmDialogService]
    })
    service = TestBed.inject(ConfirmDialogService);
  })

  it(`Deve emitir o valor correto quando chamado método 
    ${ConfirmDialogService.prototype.accept.name} no Subject configSource`, (done) => {
    const expectedValue = { accept: true };

    service.config$.subscribe(val => {
      expect(val).toEqual(expectedValue);
      done();
    })

    service.accept();
  })

  it(`Deve no emitir o valor correto quando chamado método 
    ${ConfirmDialogService.prototype.reject.name} no Subject configSource`, (done) => {
    const expectedValue = { reject: true };

    service.config$.subscribe(val => {
      expect(val).toEqual(expectedValue);
      done();
    })

    service.reject();
  })
})