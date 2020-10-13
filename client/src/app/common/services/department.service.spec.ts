import { TestBed } from '@angular/core/testing';

import { DepartmentService } from './department.service';
import { HttpClientTestingModule } from '@angular/common/http/testing';


describe('DepartmentService', () => {
  beforeEach(() => TestBed.configureTestingModule({
    imports: [
      HttpClientTestingModule
    ],
  }));

  it('should be created', () => {
    const service: DepartmentService = TestBed.get(DepartmentService);
    expect(service)
      .toBeTruthy();
  });
});
