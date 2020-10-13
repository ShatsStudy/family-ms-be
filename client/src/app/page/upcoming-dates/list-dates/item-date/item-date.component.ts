import { Component, OnInit, Input } from '@angular/core';
import { DatesItem } from '../../../common/dates-item';
import { DateService } from '../../../common/date.service';
import { UserService } from '../../../../common/services/user.service';

@Component({
  selector: 'app-date-item',
  templateUrl: './item-date.component.html',
  styleUrls: ['./item-date.component.scss']
})
export class ItemDateComponent implements OnInit {
  @Input() date: DatesItem;
  todayDate: Date;
  typeOfUser: boolean;

  constructor(
    private readonly dateService: DateService,
    private readonly userService: UserService) { }

  ngOnInit(): void {
    this.todayDate = new Date();
    this.loadTypeOfUser();
  }

  loadTypeOfUser(): void {
    if (this.userService.getUserType() === 'hrparent') {
      this.typeOfUser = true;
    }
  }

  public convertDate = (date: Date): boolean =>
    this.dateService.convertDate(this.todayDate) === this.dateService.convertDate(date);
}
