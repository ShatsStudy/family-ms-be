import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'filterUsersBy'
})
export class FilterUsersByPipe implements PipeTransform {

  transform(users: any, filterText: string): any {
    if (!filterText) {
      return users;
    }

    return users.filter(user => user.firstName.toLowerCase().startsWith(filterText.toLowerCase())
      || user.lastName.toLowerCase().startsWith(filterText.toLowerCase()));
  }
}
