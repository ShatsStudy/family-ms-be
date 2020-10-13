import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { Filter } from '../../common/filter';

import { DatepickerFilterComponent } from './datepicker-filter.component';

import { BsDatepickerModule } from 'ngx-bootstrap/datepicker';
import { BsDropdownModule } from 'ngx-bootstrap/dropdown';

describe('DatepickerFilterComponent', () => {
  let component: DatepickerFilterComponent;
  let fixture: ComponentFixture<DatepickerFilterComponent>;
  const filterItem: Filter = {
      id: 2,
      name: 'date',
      isCalendar: true,
      defaultValue: -1,
      options: [
        { name: 'Filter by Date', value: -1 },
        { name: 'date', value: 0 },
      ],
    };
  const cssClassName = '';

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      imports: [
        BsDatepickerModule.forRoot(),
        BsDropdownModule.forRoot()
      ],
      declarations: [
        DatepickerFilterComponent
      ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(DatepickerFilterComponent);
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
