import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { LinkToProfileComponent } from './link-to-profile.component';
import { RouterTestingModule } from '@angular/router/testing';


describe('LinkToProfileComponent', () => {
  let component: LinkToProfileComponent;
  let fixture: ComponentFixture<LinkToProfileComponent>;
  const label = '';

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ LinkToProfileComponent ],
      imports: [
        RouterTestingModule
      ],
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(LinkToProfileComponent);
    component = fixture.componentInstance;
    component.label = label;
    component.info = label;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
