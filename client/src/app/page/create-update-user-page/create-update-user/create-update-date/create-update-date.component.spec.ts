import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateUpdateDateComponent } from './create-update-date.component';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { RouterTestingModule } from '@angular/router/testing';
import { RouterModule } from '@angular/router';

import { NO_ERRORS_SCHEMA } from '@angular/core';

describe('CreateUpdateDateComponent', () => {
  let component: CreateUpdateDateComponent;
  let fixture: ComponentFixture<CreateUpdateDateComponent>;

  beforeEach(async(() => {
    // tslint:disable-next-line: no-floating-promises
    TestBed.configureTestingModule({
      imports: [ReactiveFormsModule, HttpClientModule, RouterTestingModule, RouterModule],
      declarations: [CreateUpdateDateComponent],
      schemas: [NO_ERRORS_SCHEMA],
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(CreateUpdateDateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
