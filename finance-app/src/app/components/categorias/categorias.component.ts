import { Component, OnInit, WritableSignal, signal } from '@angular/core';
import { CategoriasService } from '../../services/categorias.service';
import { Categorias } from '../../interfaces/Categorias';
import { DialogService, DynamicDialogRef } from 'primeng/dynamicdialog';
import { ModalCategoriaComponent } from '../../templates/modal-categoria/modal-categoria.component';
import { MessagesService } from '../../services/messages.service';
import { NotificationService } from '../../shared/services/notification.service';

@Component({
  selector: 'fin-categorias',
  templateUrl: './categorias.component.html',
  styleUrl: './categorias.component.scss',
})
export class CategoriasComponent implements OnInit {
  protected categorias: WritableSignal<Categorias[]> = signal([]);
  protected configModal = {
    modal: true,
    header: 'Atualizar Categoria',
    width: '35vw',
    contentStyle: { overflow: 'auto' },
  };

  private ref!: DynamicDialogRef;

  constructor(
    private _notificationService: NotificationService,
    private _categoriasService: CategoriasService,
    private _messagesService: MessagesService,
    private _dialogService: DialogService,
  ) {}

  ngOnInit(): void {
    this.getCategoriasList();
    this._notificationService.notifyObservable$.subscribe(
      (res) => res.refresh && this.getCategoriasList()
    );
  }

  deletedCategoria(event: any){
    if(event){
      this.ngOnInit();
    }
  }
  
  // Obtém lista de categorias
  getCategoriasList(){
    this._categoriasService.getCategorias().subscribe({
      next: (res) => (this.categorias.set(res)),
      error: () => this._messagesService.showError('Erro ao obter categorias. Tente novamente.'),
    });
  }
  
  // Metódo responsavel por abrir modal de categoria
  protected abrirModalAddCategoria() {
    this.ref = this._dialogService.open(ModalCategoriaComponent, {
      ...this.configModal,
      data: {},
    });
  }
}