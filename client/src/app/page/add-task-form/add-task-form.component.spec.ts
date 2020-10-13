import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { AddTaskFormComponent } from './add-task-form.component';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { DropdownFilterComponent } from '../filter/dropdown-filter/dropdown-filter.component';
import { appConfigProviders } from '../common/config';
import { FilterReturnService } from '../common/filter-return.service';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { HttpClientModule } from '@angular/common/http';

describe('AddTaskFormComponent', () => {
  let component: AddTaskFormComponent;
  let fixture: ComponentFixture<AddTaskFormComponent>;

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

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ AddTaskFormComponent,
                      DropdownFilterComponent,

                    ],
      imports: [ FormsModule,
                 ReactiveFormsModule,
                 HttpClientTestingModule,
                 RouterTestingModule,
                 HttpClientModule,
               ],
      providers: [ appConfigProviders,
                   { provide: FilterReturnService, useValue: filterReturnServiceMock },
                 ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(AddTaskFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
