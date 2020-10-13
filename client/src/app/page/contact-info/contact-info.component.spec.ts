import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { ContactInfoComponent } from './contact-info.component';
import { UserFilterComponent } from './user-filter/user-filter.component';
import { FilterUsersByPipe } from './filter-users-by.pipe';
import { RouterTestingModule } from '@angular/router/testing';
import { UserListComponent } from './user-list/user-list.component';
import { HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { By } from '@angular/platform-browser';
import { DebugElement } from '@angular/core';

describe('ContactInfoComponent', () => {
  let component: ContactInfoComponent;
  let fixture: ComponentFixture<ContactInfoComponent>;
  let de: DebugElement;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ContactInfoComponent, UserFilterComponent, UserListComponent, FilterUsersByPipe],
      imports: [FormsModule, HttpClientModule, RouterTestingModule, ScrollingModule]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ContactInfoComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
    de = fixture.debugElement;
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
