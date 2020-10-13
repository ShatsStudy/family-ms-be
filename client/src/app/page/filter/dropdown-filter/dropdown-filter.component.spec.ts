import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { DropdownFilterComponent } from './dropdown-filter.component';
import { appConfigProviders } from '../../common/config';
import { FilterReturnService } from '../../common/filter-return.service';

describe('DropdownFilterComponent', () => {
  let component: DropdownFilterComponent;
  let fixture: ComponentFixture<DropdownFilterComponent>;
  const filterItem = {
      id: 0,
      name: 'type',
      isCalendar: false,
      defaultValue: 0,
      options: [
        { name: 'Show all tasks', value: -1 },
        { name: 'Show delegates tasks only', value: 0 },
        { name: 'Show issues only', value: 1 },
      ],
    };
  const cssClassName = 'width-100';

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ DropdownFilterComponent ],
      providers: [ appConfigProviders,
                   { provide: FilterReturnService, useValue: filterItem },
]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(DropdownFilterComponent);
    component = fixture.componentInstance;
    component.filterItem = filterItem;
    component.cssClassName = cssClassName;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
