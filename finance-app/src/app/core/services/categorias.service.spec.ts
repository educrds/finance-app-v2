import { TestBed } from "@angular/core/testing";
import { CategoriasService } from "./categorias.service";
import { provideHttpClient, withFetch, withInterceptorsFromDi } from "@angular/common/http";
import { HttpTestingController, provideHttpClientTesting } from "@angular/common/http/testing";
import { IDropdown } from "../models/Dropdown";
import { HttpErrorHandlerService } from "../../shared/services/http-error-handler.service";
import { ConfirmationService, MessageService } from "primeng/api";
import { HttpInterceptorProvider } from "../../helpers/http-interceptor.interceptor";
import { StorageService } from "./storage.service";
import { Categoria, Categorias } from "../models/Categorias";

class MockStorageService {
  isLoggedIn(): boolean {
    return true;
  }
  get getToken(): string {
    return "fake-token";
  }
}

describe(CategoriasService.name, () => {
  let service: CategoriasService;
  let httpTestingController: HttpTestingController;
  let httpHandleErrorService: HttpErrorHandlerService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        CategoriasService,
        provideHttpClient(withFetch(), withInterceptorsFromDi()),
        provideHttpClientTesting(),
        HttpErrorHandlerService,
        ConfirmationService,
        MessageService,
        { provide: StorageService, useClass: MockStorageService },
        HttpInterceptorProvider,
      ],
    });

    httpTestingController = TestBed.inject(HttpTestingController);
    httpHandleErrorService = TestBed.inject(HttpErrorHandlerService);
    service = TestBed.inject(CategoriasService);
  });

  afterEach(() => httpTestingController.verify());

  describe(CategoriasService.prototype.getCategoriasDropdown$.name, () => {
    it(`✅Deve retornar um array de objetos contendo categorias do tipo Receita.`, () => {
      const tipoReceitaId = 1;
      const mockResponse: IDropdown[] = [
        { text: "Salário", id: 1 },
        { text: "Freelancer", id: 2 },
      ];

      service.getCategoriasDropdown$(tipoReceitaId).subscribe(val => expect(val).toEqual(mockResponse));

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/listar-select-categorias`);
      expect(req.request.method).toBe("POST");
      expect(req.request.body).toEqual({ data: { cat_tip_id: tipoReceitaId } });

      req.flush(mockResponse);
    });

    it(`✅Deve retornar um array de objetos contendo categorias do tipo Despesa.`, () => {
      const tipoDespesaId = 2;
      const mockResponse: IDropdown[] = [
        { text: "Aluguel", id: 3 },
        { text: "Contas", id: 4 },
      ];

      service.getCategoriasDropdown$(tipoDespesaId).subscribe(val => expect(val).toEqual(mockResponse));

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/listar-select-categorias`);
      expect(req.request.method).toBe("POST");
      expect(req.request.body).toEqual({ data: { cat_tip_id: tipoDespesaId } });

      req.flush(mockResponse);
    });

    it(`✅Deve tratar erro de requisição`, () => {
      spyOn(httpHandleErrorService, "handleHttpError").and.callThrough();

      const tipoDespesaId = 2;

      service.getCategoriasDropdown$(tipoDespesaId).subscribe({
        next: () => fail("Deveria ter ocorrido um erro"),
        error: () => expect(httpHandleErrorService.handleHttpError).toHaveBeenCalled(),
      });

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/listar-select-categorias`);

      expect(req.request.method).toBe("POST");
      expect(req.request.body).toEqual({ data: { cat_tip_id: tipoDespesaId } });

      req.flush("Erro simulado", { status: 500, statusText: "Internal Server Error" });
    });
  });

  describe(CategoriasService.prototype.getCategoriasByUser$.name, () => {
    it(`✅Deve realizar a requisição corretamente`, () => {
      service.getCategoriasByUser$().subscribe();

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/listar-categorias`);
      expect(req.request.method).toBe("POST");
      expect(req.request.body).toEqual({});
    });

    it(`✅Deve retornar um array de categorias ao receber uma resposta bem-sucedida`, () => {
      const mockResponse: Categorias[] = [
        {
          cat_id: 1,
          cat_nome: "Casa",
          cat_cor: "#345342",
          usr_id: 1,
          cat_tip_nome: "Despesa",
        },
      ];

      service.getCategoriasByUser$().subscribe(res => expect(res).toEqual(mockResponse));

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/listar-categorias`);
      req.flush(mockResponse);
    });

    it(`✅Deve tratar erro de requisição`, () => {
      spyOn(httpHandleErrorService, "handleHttpError").and.callThrough();

      service.getCategoriasByUser$().subscribe({
        next: () => fail("Deveria ter ocorrido um erro"),
        error: () => expect(httpHandleErrorService.handleHttpError).toHaveBeenCalled(),
      });

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/listar-categorias`);
      req.flush("Erro no servidor", { status: 500, statusText: "Internal Server Error" });
    });
  });

  describe(CategoriasService.prototype.addCategoria$.name, () => {
    const mockCategoria: Categoria = {
      cat_color: "#fff",
      id: 1,
      text: "Teste"
    }
    const mockResponse = { message: "Salvo com exito" };
    
    it(`✅Deve adicionar uma categoria e retornar uma mensagem de sucesso`, () => {
      service.addCategoria$(mockCategoria).subscribe(response => expect(response).toEqual(mockResponse));

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/adicionar-categoria`);
      
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ data: mockCategoria });
      
      req.flush(mockResponse);
    });

    it(`✅Deve tratar erro de requisição`, () => {
      spyOn(httpHandleErrorService, "handleHttpError").and.callThrough();

      service.addCategoria$(mockCategoria).subscribe({
        next: () => fail("Deveria ter ocorrido um erro"),
        error: () => expect(httpHandleErrorService.handleHttpError).toHaveBeenCalled(),
      });

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/adicionar-categoria`);
      req.flush("Erro no servidor", { status: 500, statusText: "Internal Server Error" });
    });
  })

  describe(CategoriasService.prototype.atualizarCategoria$.name, () => {
    const mockCategoria: Categorias = {
      cat_id: 1,
      cat_nome: "Casa",
      cat_cor: "#453",
      usr_id: 2,
      cat_tip_nome: "Despesa"
    }
    const mockResponse = { message: 'Registro atualizado com sucesso!' };

    it(`✅Deve tratar erro de requisição`, () => {
      spyOn(httpHandleErrorService, "handleHttpError").and.callThrough();
      service.atualizarCategoria$(mockCategoria).subscribe({
        next: () => fail("Deveria ter ocorrido um erro"),
        error: () => expect(httpHandleErrorService.handleHttpError).toHaveBeenCalled(),
      });

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/atualizar-categoria`);
      req.flush("Erro no servidor", { status: 500, statusText: "Internal Server Error" });
    })
    
    it(`✅Deve atualizar a categoria e retornar uma mensagem de sucesso`, () => {
      service.atualizarCategoria$(mockCategoria).subscribe({
        next: (response) => expect(response).toEqual(mockResponse)
      });

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/atualizar-categoria`);
      
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ data: mockCategoria });
      
      req.flush(mockResponse);
    })
  })

  describe(CategoriasService.prototype.deletarCategoria$.name, () => {
    const mockCategoria: Categorias = {
      cat_id: 2,
      cat_nome: "Freelancer",
      cat_cor: "#567",
      usr_id: 4,
      cat_tip_nome: "Receita"
    }
    const mockResponse = { message: 'Registro atualizado com sucesso!' };

    it(`✅Deve tratar erro de requisição`, () => {
      spyOn(httpHandleErrorService, "handleHttpError").and.callThrough();
      service.deletarCategoria$(mockCategoria).subscribe({
        next: () => fail("Deveria ter ocorrido um erro"),
        error: () => expect(httpHandleErrorService.handleHttpError).toHaveBeenCalled(),
      });

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/deletar-categoria`);
      req.flush("Erro no servidor", { status: 500, statusText: "Internal Server Error" });
    })
    
    it(`✅Deve deletar a categoria e retornar uma mensagem de sucesso`, () => {
      service.deletarCategoria$(mockCategoria).subscribe({
        next: (response) => expect(response).toEqual(mockResponse)
      });

      const req = httpTestingController.expectOne(`${service["_api_url"]}categoria/deletar-categoria`);
      
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ data: mockCategoria });
      
      req.flush(mockResponse);
    })
  })
})
