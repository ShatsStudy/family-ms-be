import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { UserImageComponent } from './user-image.component';

describe('UserImageComponent', () => {
  let component: UserImageComponent;
  let fixture: ComponentFixture<UserImageComponent>;
  const dummyImageUrl: string = 'assets/img/userimg.jpg';

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ UserImageComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(UserImageComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
    component.imageURL = dummyImageUrl;
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });

  it('should return imageUrl', () => {
    expect(component.imageURL)
      .toEqual('assets/img/userimg.jpg');
  });
});
