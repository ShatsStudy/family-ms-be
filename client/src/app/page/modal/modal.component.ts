import { Component, OnInit, TemplateRef, Input, EventEmitter, Output } from '@angular/core';
import { BsModalService, BsModalRef } from 'ngx-bootstrap/modal';
import { TasksService } from '../common/tasks.service';
import { UserService } from '../../common/services/user.service';
import { User } from '../../common/models/user';
import { FormBuilder, FormGroup, Validators, FormControl } from '@angular/forms';
import { FiltersService } from '../common/filters.service';
import { Filter } from '../common/filter';
import { FilterReturnService } from '../common/filter-return.service';
import { FilterOptions } from '../common/filter-options';
import { Task } from '../common/task';

@Component({
  selector: 'app-modal',
  templateUrl: './modal.component.html',
  styleUrls: ['./modal.component.scss'],
  providers: [ FilterReturnService ],
})
export class ModalComponent implements OnInit {
  modalForm: FormGroup;
  @Input() task: Task;
  @Input() item: any;
  @Input() modalType: string;
  @Output() readonly filterVal = new EventEmitter();
  modalRef: BsModalRef;
  users: User[];
  user: User;
  editTask: any;
  filter: Filter;
  usersIds: [];
  userDropDown: Filter;
  updateTask: boolean;
  errorAssignTo: boolean;

  constructor(private readonly modalService: BsModalService,
              private readonly tasksService: TasksService,
              private readonly fb: FormBuilder,
              private readonly filtersService: FiltersService,
              private readonly userService: UserService,
              private readonly filterReturnService: FilterReturnService) {
    this.modalForm = fb.group({
      id: new FormControl(),
      name: new FormControl('', [
        Validators.minLength(5),
        Validators.maxLength(20),
      ]),
      content: new FormControl('', [
        Validators.maxLength(400),
      ]),
      excerpt: new FormControl('', [
        Validators.minLength(9),
        Validators.maxLength(40),
      ]),
      status: this.fb.group({
        name: new FormControl(),
        value: new FormControl(),
      }),
      assignTo: new FormControl(),
      reassigned: new FormControl(),
    });
  }

  ngOnInit(): void {
    this.userService.getAllHr()
      .subscribe(users => {
        this.createUserDropDown(users);
      });
    this.userService.getUser()
      .subscribe(user => this.user = user);
    this.getFilterStatus();
    this.errorAssignTo = false;
  }

  get name(): any {
    return this.modalForm.get('name');
  }

  get excerpt(): any {
    return this.modalForm.get('excerpt');
  }

  get content(): any {
    return this.modalForm.get('content');
  }

  isFieldCorrectLength = (field: string): boolean =>
    this.modalForm.get(field)
      .hasError('minlength');

  public chooseAssignTo(): boolean {
    return this.userDropDown.defaultValue === -1;
  }

  private createUserDropDown(users): void {
    this.usersIds = users.map(item => (item._id));
    this.userDropDown = {
      id: 1,
      name: 'assignTo',
      isCalendar: false,
      defaultValue: -1,
      options: this.createUserDropdownOptions(users),
    };
  }

  private readonly createUserDropdownOptions = (users: User[]): FilterOptions[] => {
    let options: FilterOptions[] = users.map(
      (item: User, index: number) =>
      ({
        name: `${item.firstName} ${item.lastName}`,
        value: index,
      })
     );
    options = [{name: 'Choose Users', value: -1}, ...options];

    return options;
  };

  getFilterValUserDropDown = (i: number) => {
    this.userDropDown.defaultValue = i;
  };

  getFilterVal = (i: number) => {
    this.filter.defaultValue = i;
  };

  getFiltersNew(): any {
    this.filtersService.getFilters()
      .subscribe(filtersAll => this.filter = this.editFilter(filtersAll));
  }

  private readonly editFilter = (filtersAll: Filter[]): Filter => {
    const filterElem = {...filtersAll.filter(item => item.id === 1)[0]};
    filterElem.defaultValue = (this.task === undefined) ? 1 : this.task.status.value;
    filterElem.options = filterElem.options.filter(item => item.value > -1);

    return filterElem;
  };

  public openModal(template: TemplateRef<any>): void {
    this.modalRef = this.modalService.show(template);
    this.getFiltersNew();
  }

  public hideAfter(): void {
    setTimeout(() => {
      this.modalRef.hide();
    }, 3000);
  }

  public onSubmit(event: any): void {
    const newName = event.target.name.value;
    const newContent = event.target.content.value;
    const newExcerpt = event.target.excerpt.value;
    this.editTask = {
      id: this.task.id,
      name: newName,
      content: newContent,
      statusName: this.getStatusName(),
      statusValue: this.filter.defaultValue,
      excerpt: newExcerpt,
      assignTo: this.usersIds[this.userDropDown.defaultValue],
      reassigned: this.task.author._id,
    };
    if (this.editTask.assignTo === this.user._id) {
      this.errorAssignTo = true;
    }
    this.updateTask = false;
    this.tasksService.editTask(this.editTask)
      .subscribe((item: any) => {
        this.successHandling();
      });
  }

  private successHandling(): void {
    this.updateTask = true;
  }

  private readonly getStatusName = (): string => {
    const val = this.filter.defaultValue;
    const options: FilterOptions[] = this.filter.options.filter((opt: FilterOptions) => opt.value === val);

    return options[0].name;
  };

  getFilterStatus(): void {
    this.filter = this.filterReturnService.createFilterByName('status', 1);
  }
}
