import { User } from './user';

export class UpdateUser {
  constructor(public id?: string,
    public firstName?: string,
    public lastName?: string,
    public position?: string,
    public email?: string,
    public phone?: string,
    public contacts?: object[],
    public type?: string,
    public workingHoursFrom?: string,
    public workingHoursTo?: string,
    public birthdayDate?: string,
    public workAdress?: string,
  ) {
  }

  mapUser(user: User): void {
    this.id = user._id;
    this.firstName = user.firstName;
    this.lastName = user.lastName;
    this.position = user.position;
    this.email = user.email;
    this.phone = user.phone;
    this.contacts = user.contacts;
    this.type = user.type;
    this.type = user.type;
    this.workingHoursFrom = user.workingHoursFrom;
    this.workingHoursTo = user.workingHoursTo;
    this.birthdayDate = user.birthdayDate;
    this.workAdress = user.workAdress;
  }
}
