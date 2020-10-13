import { Component, OnInit, Inject, Input } from '@angular/core';
import { Filter } from '../common/filter';
import { FilterOptions } from '../common/filter-options';
import { FilterReturnService } from '../common/filter-return.service';
import { FormBuilder, Validators } from '@angular/forms';
import { UserService } from '../../common/services/user.service';
import { User } from '../../common/models/user';
import { TasksService } from '../common/tasks.service';
import { TaskCreateRequestBody } from '../common/task';
import { DURATION } from '../common/config';

@Component({
  selector: 'app-add-task-form',
  templateUrl: './add-task-form.component.html',
  styleUrls: ['./add-task-form.component.scss']
})
export class AddTaskFormComponent implements OnInit {
  @Input() hideHeader: boolean;
  filter: Filter;
  userDropDown: Filter;
  dropDownCssClassName: string;
  user: User;
  serverErrorMessage: {
    name: string,
    statusText: string,
    message: string
  };
  haveServerError: boolean;
  taskIsJustSend: boolean;
  isSuccessfullyDeleted: boolean;
  filterDefaultVal: number;
  newTaskId: string;
  addTaskForm = this.fb.group({
    taskName: [
      '',
      [
        Validators.required,
        Validators.minLength(5),
        Validators.maxLength(20),
      ]
    ],
    taskSummary: [
      '',
      [
        Validators.required,
        Validators.minLength(9),
        Validators.maxLength(40)
      ],
    ],
    taskDescription: [
      '',
      Validators.maxLength(400),
    ]
  });
  isUserHR: boolean;
  usersIds: [];
  typeObject: { typeName: string, typeValue: number };

  get taskName(): any {
    return this.addTaskForm.get('taskName');
  }

  get taskSummary(): any {
    return this.addTaskForm.get('taskSummary');
  }

  get taskDescription(): any {
    return this.addTaskForm.get('taskDescription');
  }

  constructor(
    private readonly filterReturnService: FilterReturnService,
    private fb: FormBuilder,
    private readonly userService: UserService,
    private readonly tasksService: TasksService,
    @Inject(DURATION) private duration: number
  ) { }

  ngOnInit(): any {
    this.dropDownCssClassName = 'width-100';
    this.haveServerError = false;
    this.taskIsJustSend = false;
    this.isSuccessfullyDeleted = false;
    this.filterDefaultVal = 1;
    this.getTheFilter();
    this.userService.getUser()
      .subscribe(user => this.user = user);
    this.isUserHR = true;
    this.userService.getAllHr()
      .subscribe(users => this.createUserDropDown(users));
    this.typeObject = this.createTaskType();
  }

  private createTaskType = (): { typeName: string, typeValue: number } =>
    (this.isUserHR) ? { typeName: 'task', typeValue: 0 } : { typeName: 'issue', typeValue: 1 };

  private createUserDropDown(users): void {
    this.usersIds = users.map(item => (item._id));
    const data = this.createUserDropdownOptions(users);
    this.userDropDown = {
      id: 1,
      name: 'assignTo',
      isCalendar: false,
      defaultValue: data.defaultValue,
      options: data.optionsArray,
    };
  }

  private createUserDropdownOptions = (users: User[]): { optionsArray: FilterOptions[], defaultValue: number } => {
    let defVal = 0;
    const options: FilterOptions[] = users.map(
      (item: User, index: number) => {
        if (item._id === this.userService.getUserId()) {
          defVal = index;
        }

        return {
          name: `${item.firstName} ${item.lastName}`,
          value: index,
        };
      }
    );

    return { optionsArray: options, defaultValue: defVal };
  };

  private readonly isUserRoleHR = (): boolean =>
    this.userService.getUserType() === 'hr';

  getFilterValUserDropDown = (i: number) => {
    this.userDropDown.defaultValue = i;
  };

  getFilterVal = (i: number, data: number) => {
    this.filter.defaultValue = data;
  };

  getTheFilter(): void {
    this.filter = this.filterReturnService.createFilterByName('status', this.filterDefaultVal);
  }

  onSubmit(): void {
    const requestBody: TaskCreateRequestBody = this.getRequestBody(this.addTaskForm.value);
    this.tasksService.createTask(requestBody)
      .subscribe((result: { id: string }) => this.successHandling(result.id),
        error => this.errorHandling(error)
      );
  }

  private successHandling(taskId: string): void {
    this.taskIsJustSend = true;
    this.addTaskForm.reset();
    this.filter.defaultValue = this.filterDefaultVal;
    this.newTaskId = taskId;

    setTimeout(() => {
      this.taskIsJustSend = false;
    }, this.duration);
  }

  private errorHandling(error: any): void {
    this.haveServerError = true;
    this.serverErrorMessage = {
      name: error.status,
      statusText: error.statusText,
      message: error.message
    };
    setTimeout(() => {
      this.haveServerError = false;
    }, this.duration);
  }

  private readonly getRequestBody = (formVal: any): TaskCreateRequestBody => ({
    name: formVal.taskName,
    excerpt: formVal.taskSummary,
    statusName: this.getStatusName(),
    statusValue: this.filter.defaultValue,
    typeName: this.typeObject.typeName,
    typeValue: this.typeObject.typeValue,
    author: this.user._id,
    content: formVal.taskDescription,
    assignTo: this.getAssignToUserId()
  });

  private readonly getAssignToUserId = (): string =>
    this.usersIds[this.userDropDown.defaultValue];

  private readonly getStatusName = (): string => {
    const val = this.filter.defaultValue;
    const options: FilterOptions[] = this.filter.options.filter((opt: FilterOptions) => opt.value === val);

    return options[0].name;
  };

  onDelete(event: MouseEvent): void {
    event.preventDefault();
    this.tasksService.deleteTask(this.newTaskId)
      .subscribe(
        () => this.deleteIsSuccess(),
        error => this.errorHandling(error)
      );
  }

  private deleteIsSuccess(): void {
    this.taskIsJustSend = false;
    this.isSuccessfullyDeleted = true;
    setTimeout(() => {
      this.isSuccessfullyDeleted = false;
    }, this.duration);
  }

  isFieldRequired = (field: string): boolean =>
    this.isFieldTouched(field) && this.addTaskForm.get(field)
      .hasError('required');

  isFieldCorrectLength = (field: string): boolean =>
    this.isFieldTouched(field) && this.addTaskForm.get(field)
      .hasError('minlength');

  private readonly isFieldTouched = (field: string): boolean =>
    this.addTaskForm.get(field).touched || this.addTaskForm.get(field).dirty;
}
