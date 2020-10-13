import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ListDatesComponent } from './list-dates.component';
import { ItemDateComponent } from './item-date/item-date.component';

describe('ListDatesComponent', () => {
  let component: ListDatesComponent;
  let fixture: ComponentFixture<ListDatesComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ListDatesComponent, ItemDateComponent,]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ListDatesComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
