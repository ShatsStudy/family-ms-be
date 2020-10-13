import { TestBed } from '@angular/core/testing';

import { FiltersService } from './filters.service';
import { appConfigProviders } from './config';

describe('FiltersService', () => {
  beforeEach(() => TestBed.configureTestingModule({
    providers: [ appConfigProviders ]
  }));

  it('should be created', () => {
    const service: FiltersService = TestBed.get(FiltersService);
    expect(service)
      .toBeTruthy();
  });
});
