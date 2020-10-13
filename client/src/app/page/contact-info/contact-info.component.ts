import { Component, OnInit } from '@angular/core';
import { User } from '../../common/models/user';
import { UserService } from '../../common/services/user.service';

@Component({
  selector: 'app-contact-info',
  templateUrl: './contact-info.component.html',
  styleUrls: ['./contact-info.component.scss']
})
export class ContactInfoComponent implements OnInit {
  users: User[];
  filterText = '';

  constructor(private readonly userService: UserService) { }

  ngOnInit(): void {
  }

  takeFilterValue(text: string): void {
    this.filterText = text;
  }

}
