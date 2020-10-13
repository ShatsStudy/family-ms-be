import { Injectable } from '@angular/core';
import { Task } from './task';
import { DatesItem } from './dates-item';
import { Filter } from './filter';
import { DateService } from './date.service';

@Injectable({
  providedIn: 'root'
})
export class FilterByPipeService {

  constructor(
    private readonly dateService: DateService) {}

  public isAllFiltersTurnedOff = (filters: Filter[]) =>
    filters.every(filter => filter.defaultValue === -1);

  public isDatesMatchesFilters = (date: DatesItem, filters: Filter[]): boolean =>
    filters.every(filter => {
      const meta: string = filter.name;
      if (filter.defaultValue === -1) {
        return true;
      }

      if (meta === 'date') {
        return this.isEqualDates(filter.defaultValue, date[meta]);
      }

      return filter.defaultValue === date[meta].value;
    });

  public isTaskMatchesFilters = (task: Task, filters: Filter[]): boolean =>
    filters.every(filter => {
      const meta: string = filter.name;

      if (meta === 'type' && filter.defaultValue === -1) {
        return !(task.resolvedByAuthor && task.resolvedByPerformer);
      }

      if (meta === 'type' && filter.defaultValue === 2) {
        return task.resolvedByAuthor && task.resolvedByPerformer;
      }

      if (meta !== 'type' && filter.defaultValue === -1) {
        return true;
      }

      if (meta === 'date') {
        return this.isEqualDates(filter.defaultValue, task[meta]);
      }

      return filter.defaultValue === task[meta].value;
    });

  private readonly isEqualDates = (date1: any, date2: any): boolean =>
    this.convertToGeneralDateFormat(date1) === this.convertToGeneralDateFormat(date2);

  private readonly convertToGeneralDateFormat = (date: Date): string => {
    const dateConverted = this.convertToDateType(date);

    return this.dateService.convertDate(dateConverted);
  };

  private readonly convertToDateType = (date: any): Date =>
    (this.dateService.isDateString(date)) ? this.dateService.convertStringToDate(date) : new Date(date);

}
