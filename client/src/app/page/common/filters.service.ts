import { Injectable, Inject } from '@angular/core';
import { Observable, of } from 'rxjs';
import { Filter } from './filter';
import { FILTERS } from './config';

@Injectable({
  providedIn: 'root'
})
export class FiltersService {
  constructor(
    @Inject(FILTERS) public filters: Filter[]
  ) { }

  getFilters(): Observable<Filter[]> {
    return of(this.filters);
  }

}
