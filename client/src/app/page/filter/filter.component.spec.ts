import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { FilterComponent } from './filter.component';
import { DropdownFilterComponent } from './dropdown-filter/dropdown-filter.component';
import { DatepickerFilterComponent } from './datepicker-filter/datepicker-filter.component';

import { BsDatepickerModule } from 'ngx-bootstrap/datepicker';
import { BsDropdownModule } from 'ngx-bootstrap/dropdown';

import { Filter } from '../common/filter';
import { FilterReturnService } from '../common/filter-return.service';
import { appConfigProviders } from '../common/config';

describe('FilterComponent', () => {
  let component: FilterComponent;
  let fixture: ComponentFixture<FilterComponent>;
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
    }
  ];
  const cssClass = 'filter-col-2';

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      imports: [
        BsDatepickerModule.forRoot(),
        BsDropdownModule.forRoot()
      ],
      declarations: [
        FilterComponent,
        DropdownFilterComponent,
        DatepickerFilterComponent
      ],
      providers: [ appConfigProviders,
                   { provide: FilterReturnService, useValue: filters },
]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(FilterComponent);
    component = fixture.componentInstance;
    component.filters = filters;
    component.cssClass = cssClass;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
