import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { UpcomingDatesComponent } from './upcoming-dates.component';
import { UserBarInfoComponent } from '../user-bar-info/user-bar-info.component';
import { FilterComponent } from '../filter/filter.component';
import { ListDatesComponent } from './list-dates/list-dates.component';
import { FilterDatesByPipe } from '../filter-dates-by.pipe';

describe('UpcomingDatesComponent', () => {
  let component: UpcomingDatesComponent;
  let fixture: ComponentFixture<UpcomingDatesComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [UpcomingDatesComponent, UserBarInfoComponent, FilterComponent, ListDatesComponent, FilterDatesByPipe]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(UpcomingDatesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
