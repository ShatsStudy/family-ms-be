import { Injectable } from '@angular/core';
import { DatesItem } from './dates-item';

@Injectable({
  providedIn: 'root'
})
export class HelperService {

  public readonly sortList = (list): DatesItem[] => {
    list.sort((b, a) => {
      if (a.date < b.date) {
        return 1;
      }
      if (a.date > b.date) {
        return -1;
      }

      return 0;
    });

    return list;
  };
}
