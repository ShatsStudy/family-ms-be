import { Component, OnInit, Input } from '@angular/core';
import { UserService } from '../../common/services/user.service';
import { User } from '../../common/models/user';

@Component({
  selector: 'app-user-bar-info',
  templateUrl: './user-bar-info.component.html',
  styleUrls: ['./user-bar-info.component.scss']
})
export class UserBarInfoComponent implements OnInit {
  @Input() userinfo: User;
  userType: string;

  constructor(readonly userService: UserService) {
  }

  ngOnInit(): void {
    this.userType = this.userService.getUserType();
  }
}
