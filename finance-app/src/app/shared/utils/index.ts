import { StorageService } from '../services/storage.service';

export default class Util {  
  static getUserNameInitials(storageService: StorageService): string | undefined {
    const user = storageService.getUser();
    if (user) {
      let rgx = new RegExp(/(\p{L}{1})\p{L}+/, 'gu');

      const arrayName = [...user.name.matchAll(rgx)] || [];
      const firstLetter = arrayName.shift()?.[1] || '';
      const secondLetter = arrayName.pop()?.[1] || '';

      const initials = (firstLetter + secondLetter).toUpperCase();
      return initials;
    }
    return 'X';
  }
}
