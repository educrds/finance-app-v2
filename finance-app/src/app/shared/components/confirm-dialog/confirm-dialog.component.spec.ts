import { ComponentFixture, TestBed } from "@angular/core/testing";
import { ConfirmDialogComponent } from "./confirm-dialog.component";
import { ConfirmDialogService } from "../../services/confirm-dialog.service";
import { DynamicDialogConfig } from "primeng/dynamicdialog";
import { ButtonModule } from "primeng/button";

describe(ConfirmDialogComponent.name, () => {
  let component: ConfirmDialogComponent;
  let fixture: ComponentFixture<ConfirmDialogComponent>;
  let confirmDialogServiceSpy: jasmine.SpyObj<ConfirmDialogService>;
  let dynamicDialogConfigStub: Partial<DynamicDialogConfig>;

  beforeEach(async () => {
    confirmDialogServiceSpy = jasmine.createSpyObj("ConfirmDialogService", ["accept", "reject"]);

    dynamicDialogConfigStub = {
      data: {
        acceptLabel: "Sim",
        rejectLabel: "Não",
        body: "Você tem certeza disso?",
      },
    };

    await TestBed.configureTestingModule({
    imports: [ButtonModule, ConfirmDialogComponent],
    providers: [
        { provide: ConfirmDialogService, useValue: confirmDialogServiceSpy },
        { provide: DynamicDialogConfig, useValue: dynamicDialogConfigStub },
    ],
}).compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(ConfirmDialogComponent);
    component = fixture.componentInstance;
  });

  it(`${ConfirmDialogComponent.name} deve ser inicializado corretamente`, () => {
    fixture.detectChanges(); // ativa a detecçao de mudanças do componente e executa o ngOnInit

    expect(component["config"]["acceptLabel"]).toBe("Sim");
    expect(component["config"]["rejectLabel"]).toBe("Não");
    expect(component["config"]["body"]).toBe("Você tem certeza disso?");
  });

  it(`Deve chamar o método ${ConfirmDialogService.prototype.accept.name} no 
    ${ConfirmDialogService.name} quando ${ConfirmDialogComponent.prototype.onAccept.name} é chamado`, () => {
    component.onAccept();
    expect(confirmDialogServiceSpy.accept).toHaveBeenCalled();
    expect(confirmDialogServiceSpy.config$);
  });

  it(`Deve chamar o método ${ConfirmDialogService.prototype.reject.name} no 
    ${ConfirmDialogService.name} quando ${ConfirmDialogComponent.prototype.onReject.name} é chamado`, () => {
    component.onReject();
    expect(confirmDialogServiceSpy.reject).toHaveBeenCalled();
    expect(confirmDialogServiceSpy.config$);
  });
});
