import { Component, OnInit } from '@angular/core';
import { CategoriasService } from '../../services/categorias.service';
import { Categorias } from '../../interfaces/Categorias';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalCategoriaComponent } from '../../templates/modal-categoria/modal-categoria.component';
import { Observable, startWith, switchMap } from 'rxjs';
import { NotificationService } from '../../../shared/services/notification.service';

@Component({
  selector: 'fin-categorias',
  templateUrl: './categorias.component.html',
  styleUrl: './categorias.component.scss',
})
export class CategoriasComponent implements OnInit {
  protected categorias$!: Observable<Categorias[]>;
  protected configModal = {
    modal: true,
    header: 'Atualizar Categoria',
    width: '35vw',
    contentStyle: { overflow: 'auto' },
  };

  private ref!: DynamicDialogRef;

  constructor(
    private _categoriasService: CategoriasService,
    private _dialogService: DialogService,
    private _notificationService: NotificationService,
  ) {}

  
  ngOnInit():void {
    this.categorias$ = this._notificationService.notifyObservable$.pipe(
      startWith({ refresh: true }),
      switchMap(res => res.refresh ? this._categoriasService.getCategorias$() : [])
    );
  }

  deletedCategoria(event: any): void {
    if(event){
      this.ngOnInit();
    }
  }
  
  // Metódo responsavel por abrir modal de categoria
  protected abrirModalAddCategoria():void {
    this.ref = this._dialogService.open(ModalCategoriaComponent, {
      ...this.configModal,
      data: {},
    });
  }
}