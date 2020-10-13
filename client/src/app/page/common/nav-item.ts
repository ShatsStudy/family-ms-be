export class NavItem {
  id: string;
  title: string;
  current: boolean;
  router?: string;
  rightMenu: boolean;
  burgerMenu: boolean;
  parent: string;
  child: string;
  logout?: boolean;
}

export class NavItemSet {
  type: string;
  style: string;
}
