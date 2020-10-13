import { FilterOptions } from './filter-options';

export class Filter {
  id: number;
  name: string;
  isCalendar: boolean;
  defaultValue: any;
  options: FilterOptions[];
}
