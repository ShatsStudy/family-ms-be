import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { UserBarInfoComponent } from './user-bar-info.component';
import { UserImageComponent } from './user-image/user-image.component';
import { LinkToProfileComponent } from './link-to-profile/link-to-profile.component';
import { NO_ERRORS_SCHEMA } from '@angular/core';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { User } from '../../common/models/user';
import { UserService } from '../../common/services/user.service';

describe('UserBarInfoComponent', () => {
  let component: UserBarInfoComponent;
  let fixture: ComponentFixture<UserBarInfoComponent>;
  let userService: UserService;
  const dummyUser: User = {
    watched_issues: [],
    roles: [],
    _id: '5cbb6d7ba4908a0db878c37a',
    firstName: 'Dmytro',
    lastName: 'Sobakapirat',
    position: 'Senior pomidor developer',
    email: 'sobaka-ne-vmerla@gmail.com',
    phone: '3801111111',
    photoURL: 'http://res.cloudinary.com/dd1mk/image/upload/v1555326362/hrms/avatars/iq5boujmnj2u0udtiyl7.jpg',
    type: 'dev',
    manager: {
      _id: '5c9a065b8c40cb0e8cd39d11',
      firstName: 'Skype',
      lastName: 'FileExchanger',
      position: 'Middle QA',
      email: 'dplscode@gmail.com',
      phone: '3802281488',
      contacts: [
        {
          contact_name: 'skype',
          contact_value: 'myskype'
        }
      ],
    },
    teamlead: {
      photoURL: '',
      firstName: 'Skype',
      lastName: 'FileExchanger',
      position: 'Middle QA',
      email: 'dplscode@gmail.com',
      phone: '3802281488',
      contacts: [
        {
          contactName: 'skype',
          contactValue: 'myskype'
        }
      ],
      department: { _id: '5cab274ece3843324cc6d774' },
      manager: {
        contacts: [{
          contact_name: 'skype',
          contact_value: 'myskype'
        }],
        email: 'dplscode@gmail.com',
        firstName: 'Skype',
        lastName: 'FileExchanger',
        phone: '3802281488',
        position: 'Middle QA',
        _id: '5c9a065b8c40cb0e8cd39d11',
      },
    },
    contacts: [],
    dates: [],
    department: {
      position: [],
      _id: '5cab274ece3843324cc6d774',
      name: 'Sales '
    }
  };

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [
        LinkToProfileComponent,
        UserImageComponent,
        UserBarInfoComponent,
        UserImageComponent,
      ],
      imports: [
        HttpClientTestingModule,
        RouterTestingModule
      ],
      schemas: [NO_ERRORS_SCHEMA]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(UserBarInfoComponent);
    component = fixture.componentInstance;
    component.userinfo = dummyUser;
    userService = TestBed.get(UserService);
    spyOn(userService, 'getUserType').and
      .returnValue('customUserType');
    fixture.detectChanges();
  });

  it('should return Manager name and surname', () => {
    expect(component.getManagerName())
      .toEqual('Skype FileExchanger');
  });

  it('should return TeamLead name and surname', () => {
    expect(component.getTeamleadName())
      .toEqual('Skype FileExchanger');
  });

  it('return userType from Service', () => {
    expect(component.userType)
      .toEqual('customUserType');
  });
});
