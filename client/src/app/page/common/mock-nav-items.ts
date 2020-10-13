import { NavItem } from './nav-item';


export const NAVBAR_LIST: NavItem[] = [
  {
    id: 'upcoming-tasks',
    title: 'upcoming tasks',
    current: false,
    router: '/profile/upcoming-tasks',
    rightMenu: false,
    burgerMenu: true,
    parent: 'parent',
    child: 'child'
  },
  {
    id: 'issues',
    title: 'issues',
    current: false,
    router: '/profile/upcoming-tasks',
    rightMenu: false,
    burgerMenu: true,
    parent: '',
    child: 'child'
  },
  {
    id: 'upcoming-dates',
    title: 'upcoming dates',
    current: false,
    router: '/profile/upcoming-dates',
    rightMenu: false,
    burgerMenu: true,
    parent: 'parent',
    child: 'child'
  },
  {
    id: 'contact-info',
    title: 'contact info',
    current: false,
    router: '/profile/contact-info',
    rightMenu: false,
    burgerMenu: true,
    parent: 'parent',
    child: 'child'
  },
  {
    id: 'log-out',
    title: 'log out',
    current: false,
    router: '',
    rightMenu: true,
    burgerMenu: false,
    parent: 'parent',
    child: 'child',
    logout: true
  },
  {
    id: 'my-profile',
    title: 'my profile',
    current: false,
    router: '/profile/my-profile',
    rightMenu: true,
    burgerMenu: true,
    parent: 'parent',
    child: 'child'
  },
  {
    id: 'edit-profile',
    title: 'edit profile',
    current: false,
    router: '/profile/edit-user/:id',
    rightMenu: true,
    burgerMenu: false,
    parent: 'parent',
    child: ''
  },
  {
    id: 'create-user',
    title: 'create user',
    current: false,
    router: '/profile/create-user',
    rightMenu: false,
    burgerMenu: true,
    parent: 'parent',
    child: ''
  }
];
