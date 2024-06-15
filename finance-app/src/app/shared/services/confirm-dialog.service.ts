import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ConfirmDialogService {
  #configSource = new Subject<any>();
  public config$ = this.#configSource.asObservable();

  accept(): void {
    this.#configSource.next({ accept: true });
  }

  reject(): void {
    this.#configSource.next({ reject: true });
  }
}
