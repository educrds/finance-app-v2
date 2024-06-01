import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ConfirmDialogService {
  private configSource = new Subject<any>();
  config$ = this.configSource.asObservable();

  constructor() { }

  accept(): void {
    this.configSource.next({ accept: true });
  }

  reject(): void {
    this.configSource.next({ reject: true });
  }
}
