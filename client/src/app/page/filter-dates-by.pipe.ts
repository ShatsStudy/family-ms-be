import { Pipe, PipeTransform } from '@angular/core';
import { Filter } from './common/filter';
import { DatesItem } from './common/dates-item';
import { FilterByPipeService } from './common/filter-by-pipe.service';

@Pipe({
  name: 'filterDatesBy'
})
export class FilterDatesByPipe implements PipeTransform {
  constructor(
    private readonly filterByPipeService: FilterByPipeService
  ) {}

  transform(dates: DatesItem[], filters?: Filter[]): DatesItem[] {
    if (!filters || this.filterByPipeService.isAllFiltersTurnedOff(filters)) {
      return dates;
    }

    return dates.filter(date => this.filterByPipeService.isDatesMatchesFilters(date, filters));
  }

}
