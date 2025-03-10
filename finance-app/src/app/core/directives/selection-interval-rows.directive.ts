import { Directive, HostListener, input, output } from '@angular/core';
import { Transacao } from '../models/Transacao';

@Directive({
    selector: '[selectionIntevalRows]',
    standalone: true
})
export class SelectionIntervalRowsDirective {
  public rowSelected = input<Transacao[]>([]);
  public transacoes = input<Transacao[]>([]);

  public selectionChange = output<Transacao[]>();

  @HostListener('window:keydown', ['$event'])
  pressShiftKey(event: KeyboardEvent) {
    if (event.shiftKey && this.rowSelected().length > 1) {
      const firstObject = this.rowSelected()[0];
      const firstElementIndex = this.transacoes().findIndex(item => item.trs_id === firstObject.trs_id);
  
      const secondObject = this.rowSelected()[this.rowSelected().length - 1];
      const secondElementIndex = this.transacoes().findIndex(item => item.trs_id === secondObject.trs_id);
  
      if (firstElementIndex !== -1 && secondElementIndex !== -1) {
        const startIndex = Math.min(firstElementIndex, secondElementIndex);
        const endIndex = Math.max(firstElementIndex, secondElementIndex) + 1;
  
        const newSelection = this.transacoes().slice(startIndex, endIndex);
        this.selectionChange.emit(newSelection);
      }
    }
  }
}
