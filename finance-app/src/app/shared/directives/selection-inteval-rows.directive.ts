import { Directive, EventEmitter, HostListener, Input, Output } from '@angular/core';
import { Transacao } from '../../interfaces/Transacao';

@Directive({
  selector: '[selectionIntevalRows]'
})
export class SelectionIntevalRowsDirective {
  @Input() rowSelected: Transacao[] = [];
  @Input() transacoes: Transacao[] = [];

  @Output() selectionChange = new EventEmitter<Transacao[]>();

  @HostListener('window:keydown', ['$event'])
  pressShiftKey(event: KeyboardEvent) {
    if (event.shiftKey && this.rowSelected.length > 1) {
      const firstObject = this.rowSelected[0];
      const firstElementIndex = this.transacoes.findIndex(item => item.trs_id === firstObject.trs_id);
  
      const secondObject = this.rowSelected[this.rowSelected.length - 1];
      const secondElementIndex = this.transacoes.findIndex(item => item.trs_id === secondObject.trs_id);
  
      if (firstElementIndex !== -1 && secondElementIndex !== -1) {
        const startIndex = Math.min(firstElementIndex, secondElementIndex);
        const endIndex = Math.max(firstElementIndex, secondElementIndex) + 1;
  
        const newSelection = this.transacoes.slice(startIndex, endIndex);
        this.selectionChange.emit(newSelection);
      }
    }
  }
}
