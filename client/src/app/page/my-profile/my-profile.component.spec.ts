import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { MyProfileComponent } from './my-profile.component';
import { UserBarInfoComponent } from '../user-bar-info/user-bar-info.component';

import { HttpClientModule } from '@angular/common/http';
import { RouterTestingModule } from '@angular/router/testing';
import { RouterModule } from '@angular/router';

import { AccordionModule, BsModalService, ModalModule } from 'ngx-bootstrap';


import { NO_ERRORS_SCHEMA } from '@angular/core';

describe('MyProfileComponent', () => {
  let component: MyProfileComponent;
  let fixture: ComponentFixture<MyProfileComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      providers: [ BsModalService ],
      imports: [HttpClientModule, RouterTestingModule, RouterModule,  AccordionModule.forRoot(), ModalModule.forRoot() ],
      declarations: [ MyProfileComponent, UserBarInfoComponent ],
      schemas: [NO_ERRORS_SCHEMA]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(MyProfileComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
