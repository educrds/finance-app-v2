import { TestBed } from "@angular/core/testing";
import { CustomMessageService } from "./messages.service";
import { ConfirmationService, MessageService } from "primeng/api";

describe(CustomMessageService.name, () => {
  let service: CustomMessageService;
  let messageServiceSpy: jasmine.SpyObj<MessageService>;
  let confirmationServiceSpy: jasmine.SpyObj<ConfirmationService>;

  beforeEach(() => {
    const spy = jasmine.createSpyObj("MessageService", ["add"]);
    const confirmationSpy = jasmine.createSpyObj("ConfirmationService", ["confirm"]);

    TestBed.configureTestingModule({
      providers: [
        MessageService,
        CustomMessageService,
        { provide: MessageService, useValue: spy },
        { provide: ConfirmationService, useValue: confirmationSpy },
      ],
    });

    confirmationServiceSpy = TestBed.inject(ConfirmationService) as jasmine.SpyObj<ConfirmationService>;
    messageServiceSpy = TestBed.inject(MessageService) as jasmine.SpyObj<MessageService>;
    service = TestBed.inject(CustomMessageService);
  });

  it(`✅Método ${CustomMessageService.prototype.showSuccess.name} deve chamar MessageService.add() com a mensagem de sucesso correta.`, () => {
    const message = "Dados adicionados com sucesso.";
    service.showSuccess(message);

    expect(messageServiceSpy.add).toHaveBeenCalledWith({
      severity: "success",
      summary: "Sucesso",
      detail: message,
    });
    expect(messageServiceSpy.add.calls.count()).toBe(1)
  });

  it(`✅Método ${CustomMessageService.prototype.showError.name} deve chamar MessageService.add() com a mensagem de sucesso correta.`, () => {
    const message = "Dados adicionados com sucesso.";
    service.showError(message);

    expect(messageServiceSpy.add).toHaveBeenCalledWith({
      severity: "error",
      summary: "Erro",
      detail: message,
    });
    expect(messageServiceSpy.add.calls.count()).toBe(1)
  });

  it(`✅Método ${CustomMessageService.prototype.confirm.name} deve chamar ConfirmationService.confirm() com os parametros corretos.`, () => {
    const message = 'Tem certeza?';
    const header = 'Confirmação';
    const acceptCallback = jasmine.createSpy("acceptCallback");
    const rejectCallback = jasmine.createSpy("rejectCallback");

    service.confirm(message, header, acceptCallback, rejectCallback);

    expect(confirmationServiceSpy.confirm).toHaveBeenCalledWith({
      message: message,
      header: header,
      icon: "pi pi-exclamation-triangle",
      acceptIcon: "none",
      rejectIcon: "none",
      rejectButtonStyleClass: "p-button-text",
      accept: acceptCallback,
      reject: rejectCallback,
    });
    expect(confirmationServiceSpy.confirm.calls.count()).toBe(1);
  });
});
