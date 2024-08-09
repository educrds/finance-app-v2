import { TestBed } from "@angular/core/testing";
import { HttpErrorHandlerService } from "./http-error-handler.service";
import { MessagesService } from "../../core/services/messages.service";
import { StorageService } from "../../core/services/storage.service";
import { Router } from "@angular/router";
import { HttpErrorResponse } from "@angular/common/http";

describe(HttpErrorHandlerService.name, () => {
  let service: HttpErrorHandlerService;

  let routerSpy: jasmine.SpyObj<Router>;
  let messagesServiceSpy: jasmine.SpyObj<MessagesService>;
  let storageServiceSpy: jasmine.SpyObj<StorageService>;

  beforeEach(() => {
    routerSpy = jasmine.createSpyObj("Router", ["navigate"]);
    messagesServiceSpy = jasmine.createSpyObj("MessagesService", ["showError"]);
    storageServiceSpy = jasmine.createSpyObj("StorageService", ["clean"]);

    TestBed.configureTestingModule({
      providers: [
        HttpErrorHandlerService,
        { provide: Router, useValue: routerSpy },
        { provide: MessagesService, useValue: messagesServiceSpy },
        { provide: StorageService, useValue: storageServiceSpy },
      ],
    });
    service = TestBed.inject(HttpErrorHandlerService);
  });

  it(`${HttpErrorHandlerService.prototype.handleHttpError.name} deve lidar com erro 401 limpando o localStorage e redirecionando para tela de login`, () => {
    const errorResponse: HttpErrorResponse = new HttpErrorResponse({ status: 401 });

    service.handleHttpError(errorResponse).subscribe({
      error: () => {
        expect(storageServiceSpy.clean).toHaveBeenCalled();
        expect(routerSpy.navigate).toHaveBeenCalledWith(['/auth/login'])
      }
    })
  });

  it(`${HttpErrorHandlerService.prototype.handleHttpError.name} deve lidar com erro 404 exibindo um alerta ao usuário`, () => {
    const errorResponse: HttpErrorResponse = new HttpErrorResponse({ status: 404 });

    service.handleHttpError(errorResponse).subscribe({
      error: () => {
        expect(messagesServiceSpy.showError).toHaveBeenCalledWith('Recurso não encontrado. Status: 404')
      }
    })
  });
  
  it(`${HttpErrorHandlerService.prototype.handleHttpError.name} deve lidar com erro 500 exibindo um alerta ao usuário`, () => {
    const errorResponse: HttpErrorResponse = new HttpErrorResponse({ status: 500 });

    service.handleHttpError(errorResponse).subscribe({
      error: () => {
        expect(messagesServiceSpy.showError).toHaveBeenCalledWith('Erro interno do servidor. Status: 500')
      }
    })
  });

  it(`${HttpErrorHandlerService.prototype.handleHttpError.name} deve lidar com erro desconhecido exibindo um alerta ao usuário`, () => {
    const errorResponse: HttpErrorResponse = new HttpErrorResponse({ status: 413 });

    service.handleHttpError(errorResponse).subscribe({
      error: () => {
        expect(messagesServiceSpy.showError).toHaveBeenCalledWith('Erro não tratado. Status: 413')
      }
    })
  });
});
