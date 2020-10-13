import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { DropdownInfoComponent } from './dropdown-info.component';
import { BsDropdownModule } from 'ngx-bootstrap';
import { HttpClientTestingModule } from '@angular/common/http/testing';


describe('DropdownInfoComponent', () => {
  let component: DropdownInfoComponent;
  let fixture: ComponentFixture<DropdownInfoComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ DropdownInfoComponent ],
      imports: [
        BsDropdownModule.forRoot(),
        HttpClientTestingModule
      ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(DropdownInfoComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
