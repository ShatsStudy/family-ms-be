import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { CreateUpdateSideBarInfoComponent } from './create-update-side-bar-info.component';
import { NO_ERRORS_SCHEMA } from '@angular/core';
import { HttpClientTestingModule } from '@angular/common/http/testing';



describe('CreateSideBarInfoComponent', () => {
  let component: CreateUpdateSideBarInfoComponent;
  let fixture: ComponentFixture<CreateUpdateSideBarInfoComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [
        CreateUpdateSideBarInfoComponent
      ],
      imports: [
        HttpClientTestingModule
      ],
      schemas: [NO_ERRORS_SCHEMA]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(CreateUpdateSideBarInfoComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
