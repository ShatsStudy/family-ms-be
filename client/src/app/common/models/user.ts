import { DatesItem } from '../../page/common/dates-item';

export class Contact {
  constructor(public contactName?: string,
    public contactValue?: string) { }
}

export class Department {
  constructor(public _id?: string,
    public name?: string,
    public position?: []) { }
}

export class Manager {
  constructor(public _id?: any,
    public firstName?: string,
    public lastName?: string,
    public position?: string,
    public manager?: Manager,
    public teamlead?: User,
    public department?: Department,
    public email?: string,
    public phone?: string,
    public contacts?: object,
    public photoURL?: string,
    public hrID?: number,
    public date?: object) { }
}

export class User {
  constructor(public _id?: any,
    public firstName?: string,
    public lastName?: string,
    public position?: string,
    public email?: string,
    public phone?: string,
    public contacts?: Contact[],
    public photoURL?: string,
    public photoID?: string,
    public dates?: DatesItem[],
    public watched_issues?: string[],
    public workingHoursFrom?: string,
    public birthdayDate?: string,
    public workingHoursTo?: string,
    public workAdress?: string,
    public type?: string) { }
}
