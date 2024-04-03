import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class DateFilterService {

  constructor() { }

  public notify = new BehaviorSubject<any>('');
  notifyObservable$ = this.notify.asObservable();

  public notifyChanges(data: any) {
    if(data){
      this.notify.next(data)
    }
  }
}
