import { Component, OnInit } from '@angular/core';
import { UserService } from '../common/services/user.service';
import { TasksService } from '../page/common/tasks.service';
import { User } from '../common/models/user';

@Component({
  selector: 'app-page',
  templateUrl: './page.component.html',
  styleUrls: ['./page.component.scss']
})
export class PageComponent implements OnInit {
  user = new User();

  constructor(private readonly userService: UserService,
              private readonly tasksService: TasksService) { }

  ngOnInit(): void {
    this.loadUser();
    this.loadTasks(this.userService.getUserId());
  }

  loadUser(): void {
    this.userService.getUser()
      .subscribe();
  }

  loadTasks(userID): void {
    this.tasksService.getUserTasks(userID)
      .subscribe();
  }

  updateDataFilterOptions = (options: any, dateValue: any): [] => {
    if (dateValue === -1) {
      return options;
    }

    return options.map(opt =>
      opt.name === 'date' ? { name: opt.name, value: dateValue } : opt);
  };
}
