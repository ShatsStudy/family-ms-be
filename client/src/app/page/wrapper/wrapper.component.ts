import { Component, OnInit, ChangeDetectorRef, Inject } from '@angular/core';
import { UserService } from '../../common/services/user.service';
import { User } from '../../common/models/user';
import { FilterOptions } from '../common/filter-options';
import { Filter } from '../common/filter';
import { FiltersService } from '../common/filters.service';
import { Task } from '../common/task';
import { TasksService } from '../common/tasks.service';
import { FILTER_CSS_CLASS_PREFIX } from '../common/config';

@Component({
  selector: 'app-wrapper',
  templateUrl: './wrapper.component.html',
  styleUrls: ['./wrapper.component.scss'],
})

export class WrapperComponent implements OnInit {
  emptyTask: Task;
  user: User;
  userID: string;
  task: Task;
  filters: Filter[];
  tasks: Task[];
  modalTypeVal: string;
  filterGrids: string;
  users: User[];
  userRole: string;

  constructor(
    private readonly userInfoService: UserService,
    private readonly filtersService: FiltersService,
    private readonly tasksService: TasksService,
    private readonly ref: ChangeDetectorRef,
    @Inject(FILTER_CSS_CLASS_PREFIX) public filterCssClassPrefix: string
  ) { }

  ngOnInit(): void {
    this.modalTypeVal = 'CREATE';
    this.getFilters();
    this.getTasks();
    this.loadUser();
    this.userRole = this.checkUserRole();
  }

  loadUser(): void {
    this.userInfoService.getUser()
      .subscribe(user => this.user = user);
  }

  private readonly checkUserRole = (): any =>
    this.userInfoService.getUserType();

  getFilters(): void {
    this.filtersService.getFilters()
      .subscribe(filters => {
        this.filters = filters;
        this.filterGrids = filters.length ? this.filterCssClassPrefix + filters.length.toString() : '';
      });
  }

  getTasks(): void {
    this.tasksService.takeUserTasks
      .subscribe(tasks => this.tasks = tasks);
  }

  updateResolve(): void {
    this.tasksService.updateResolvedBy(this.userInfoService.getUserId(), this.task.id)
      .subscribe(tasks => { this.tasks = tasks; });
  }

  selectFilterOption = (data: any) => {
    if (this.filters.length) {
      this.filters = this.filters.map(
        (item, index) => index === data.filterId ? {
          id: item.id,
          name: item.name,
          isCalendar: item.isCalendar,
          defaultValue: data.optionId,
          options: this.setOptions(item.isCalendar, item.options, data.optionId)
        } : item
      );
    }
  };

  private readonly setOptions = (isCalendar: boolean, options: FilterOptions[], data: any) => {
    if (isCalendar) {
      return this.updateOptions(options, data);
    }

    return options;
  };

  private readonly updateOptions = (options: any, dateValue: any): [] => {
    if (dateValue === -1) {
      return options;
    }

    return options.map(opt =>
      opt.name === 'date' ? { name: opt.name, value: dateValue } : opt);
  };
}
