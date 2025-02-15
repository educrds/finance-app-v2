import { Component, OnInit, inject } from '@angular/core';
import { DynamicDialogConfig } from 'primeng/dynamicdialog';
import { ConfirmDialogService } from '../../services/confirm-dialog.service';
import { Button } from 'primeng/button';

@Component({
    selector: 'coinz-confirm-dialog',
    templateUrl: './confirm-dialog.component.html',
    styleUrl: './confirm-dialog.component.scss',
    standalone: true,
    imports: [Button]
})
export class ConfirmDialogComponent implements OnInit {
  protected config: {[ key:string]: string | null } = {
    acceptLabel: 'Confirmar',
    rejectLabel: 'Cancelar',
    body: null
  };

  private _config = inject(DynamicDialogConfig);
  private _confirmDialogService = inject(ConfirmDialogService);

  ngOnInit(): void {
    if(this._config.data){  
      this.config = this._config.data;
    }
  }

  onAccept(){
    this._confirmDialogService.accept();
  }
  
  onReject(){
    this._confirmDialogService.reject();
  }
}
