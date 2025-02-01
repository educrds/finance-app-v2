import { Component, OnInit, inject } from '@angular/core';
import { CategoriasService } from '../../services/categorias.service';
import { Categorias } from '../../models/Categorias';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalCategoriaComponent } from '../../templates/modal-categoria/modal-categoria.component';
import { Observable, startWith, switchMap } from 'rxjs';
import { NotificationService } from '../../services/notification.service';
import { WrapContainerComponent } from '../wrap-container/wrap-container.component';
import { Button } from 'primeng/button';
import { CategoriaTableComponent } from '../categoria-table/categoria-table.component';
import { AsyncPipe } from '@angular/common';

@Component({
    selector: 'fin-categorias',
    templateUrl: './categorias.component.html',
    styleUrl: './categorias.component.scss',
    standalone: true,
    imports: [
        WrapContainerComponent,
        Button,
        CategoriaTableComponent,
        AsyncPipe,
    ],
})
export class CategoriasComponent implements OnInit {
  #ref: DynamicDialogRef | undefined;

  #_categoriasService =  inject(CategoriasService);
  #_dialogService =  inject(DialogService);
  #_notificationService =  inject(NotificationService);
  
  protected categorias$: Observable<Categorias[]> | undefined;
  protected configModal = {
    modal: true,
    header: 'Nova Categoria',
    width: '30vw',
    closable: true,
    contentStyle: { overflow: 'auto' },
  };
  
  ngOnInit(): void {
    this.categorias$ = this.#_notificationService.notifyObservable$.pipe(
      startWith({ refresh: true }),
      switchMap(res => res.refresh ? this.#_categoriasService.getCategoriasByUser$() : [])
    );
  }

  protected deletedCategoria(event: boolean): void {
    if(event){
      this.ngOnInit();
    }
  }
  
  // Metódo responsavel por abrir modal de categoria
  protected abrirModalAddCategoria(): void {
    this.#ref = this.#_dialogService.open(ModalCategoriaComponent, {
      ...this.configModal,
      data: {},
    });
  }
}