import { InjectionToken } from '@angular/core';
import { Filter } from './filter';

export const DURATION = new InjectionToken<number>('duration');
const duration = 10000;

export const FILTER_CSS_CLASS_PREFIX = new InjectionToken<string>('filterCssClassPrefix');
const filterCssClassPrefix = 'filter-col-';

export const FILTERS = new InjectionToken<Filter[]>('filters-mock');
const filters: Filter[] = [
  {
    id: 0,
    name: 'type',
    isCalendar: false,
    defaultValue: -1,
    options: [
      { name: 'Show all tasks', value: -1 },
      { name: 'Show delegates tasks only', value: 0 },
      { name: 'Show issues only', value: 1 },
      { name: 'Show resolved tasks only', value: 2 }
    ],
  },
  {
    id: 1,
    name: 'status',
    isCalendar: false,
    defaultValue: -1,
    options: [
      { name: 'Filter by Status', value: -1 },
      { name: 'High', value: 0 },
      { name: 'Normal', value: 1 },
      { name: 'Low', value: 2 },
    ],
  },
  {
    id: 2,
    name: 'date',
    isCalendar: true,
    defaultValue: -1,
    options: [
      { name: 'Filter by Date', value: -1 },
      { name: 'date', value: 0 },
    ],
  }
];

export const appConfigProviders = [
  {
    provide: FILTERS,
    useValue: filters
  },
  {
    provide: DURATION,
    useValue: duration
  },
  {
    provide: FILTER_CSS_CLASS_PREFIX,
    useValue: filterCssClassPrefix
  }
];
