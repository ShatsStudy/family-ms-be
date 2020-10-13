import { FilterUsersByPipe } from './filter-users-by.pipe';
import { User } from '../../common/models/user';
import { } from '../contact-info/contact-info.component';
import { throwError } from 'rxjs';

describe('FilterUsersByPipe', () => {
  let filter: string;
  const dummyUsers: Array<User> = [
    {
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
    }
  ];

  it('create an instance', () => {
    const pipe = new FilterUsersByPipe();
    expect(pipe)
      .toBeTruthy();
  });

  it('if there is no filters return all users', () => {
    const pipe = new FilterUsersByPipe();
    filter = '';
    expect(pipe.transform(dummyUsers, filter))
      .toBe(dummyUsers);
  });

  it('filter users by firstName', () => {
    const pipe = new FilterUsersByPipe();
    filter = 'GIveMe';
    expect(pipe.transform(dummyUsers, filter))
      .toEqual(dummyUsers.filter(user => user._id === '5cbb6d7ba4908a0db878c56c'));
  });

  it('filter users by lastName', () => {
    const pipe = new FilterUsersByPipe();
    filter = 'Sobakapirat';
    expect(pipe.transform(dummyUsers, filter))
      .toEqual(dummyUsers.filter(user => user._id === '5cbb6d7ba4908a0db878c37a'));
  });
});
