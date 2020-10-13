import { TestBed } from '@angular/core/testing';

import { FilterByPipeService } from './filter-by-pipe.service';

describe('FilterByPipeService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: FilterByPipeService = TestBed.get(FilterByPipeService);
    expect(service).toBeTruthy();
  });
});
