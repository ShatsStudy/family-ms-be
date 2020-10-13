import { Injectable, Inject } from '@angular/core';
import { Filter } from './filter';
import { FilterOptions } from './filter-options';
import { FILTERS } from './config';
import { Observable, of } from 'rxjs';

@Injectable()
export class FilterReturnService {
  constructor(
    @Inject(FILTERS) public filters: Filter[]
  ) { }

  private currentFilterReturn: Filter;

  set filterReturn(filter: Filter) {
    this.currentFilterReturn  = {...filter};
  }

  get filterReturn(): Filter {
    return this.currentFilterReturn;
  }

  getTitle = (filter: Filter): string => {
    let titleObj: FilterOptions;
    titleObj = filter.options.filter(
      (item: FilterOptions) => filter.defaultValue === item.value)[0];

    return titleObj.name;
  };

  createFilterByName = (filterName: string, defaultValue: number = -1): Filter => {
    let filterEl = this.filters.filter((item: Filter) => item.name === filterName);
    filterEl = [...filterEl];
    const theFilter: Filter = {...filterEl[0]};
    theFilter.defaultValue = defaultValue;
    let options: FilterOptions[];
    options = theFilter.options.filter(opt => opt.value > -1);
    theFilter.options = [...options];

    return theFilter;
  };

  saveFilterReturn(i: number): Observable<string> {
    this.filterReturn = this.currentFilterReturn;
    this.currentFilterReturn.defaultValue = i;

    return of(this.getTitle(this.currentFilterReturn));
  }

}
