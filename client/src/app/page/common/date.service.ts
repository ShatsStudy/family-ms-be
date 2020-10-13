import { Injectable } from '@angular/core';
import { DatesItem } from './dates-item';
import { HelperService } from './helper.service';

@Injectable({
  providedIn: 'root'
})

export class DateService {

  constructor(private readonly helperService: HelperService) { }

  public isDateString = (dateStr: string): boolean => {
    const str = `${dateStr}`;
    const time = str.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
    if (time === null) {
      return false;
    }
    const day = +time[1];
    const month = +time[2];

    return month > 0 && month <= 12 && day > 0 && day <= 31;
  };

  public readonly convertStringToDate = (dateStr: string) => {
    const dateParts = dateStr.split('/');

    return new Date(+ dateParts[2], (+ dateParts[1]) - 1, + dateParts[0]);
  };

  public readonly convertDate = (inputDate: Date): string => {
    const date = new Date(inputDate);
    const dd = this.getDayStr(date);
    const mm = this.getMonthStr(date);
    const yyyy = date.getFullYear()
      .toString();
    const separator = '/';

    return dd + separator + mm + separator + yyyy;
  };

  private readonly getDayStr = (date: Date): string => {
    const day = date.getDate();
    if (day < 10) {
      const str = '0';

      return str + day.toString();
    }

    return day.toString();
  };

  private readonly getMonthStr = (date: Date): string => {
    const month = date.getMonth() + 1;
    if (month < 10) {
      const str = '0';

      return str + month.toString();
    }

    return month.toString();
  };

  public readonly setDateList = (user, dateArray): DatesItem[] => {
    let dateList = dateArray;
    user.dates.map((date) => {
      const dateObj = {
        firstName: user.firstName,
        lastName: user.lastName,
        topic: date.topic,
        date: date.date
      };
      dateList = [...dateList, dateObj];
      dateList = this.helperService.sortList(dateList);
  });

    return dateList;
  };
}
