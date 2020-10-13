import { TestBed } from '@angular/core/testing';

import { FilterReturnService } from './filter-return.service';
import { appConfigProviders } from './config';

describe('FilterReturnService', () => {
  const filterReturnServiceMock = {
    createFilterByName: () => {
      const filters = {
        defaultValue: 1,
        id: 1,
        isCalendar: false,
        name: 'status',
        options: [
          { name: 'High', value: 0 },
          { name: 'Normal', value: 1 },
          { name: 'Low', value: 2 }
        ]
      };

      return filters;
    }
  };
  beforeEach(() => TestBed.configureTestingModule({
    providers: [ appConfigProviders,
                 { provide: FilterReturnService, useValue: filterReturnServiceMock },
    ]
  }));

  it('should be created', () => {
    const service: FilterReturnService = TestBed.get(FilterReturnService);
    expect(service)
      .toBeTruthy();
  });
});
