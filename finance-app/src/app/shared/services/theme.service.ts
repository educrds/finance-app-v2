import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class ThemeService {
  private theme = new BehaviorSubject<string>(this._getUserThemePreference());
  themeObservable$ = this.theme.asObservable();

  private _getUserThemePreference():string {
    const theme = localStorage.getItem('theme') ?? 'light';
    return theme
  }

  public toggleTheme(themeSelected:string):void {
    document.documentElement.classList.toggle('dark-mode');
    localStorage.setItem('theme', themeSelected);
    this.theme.next(themeSelected);
  }
}