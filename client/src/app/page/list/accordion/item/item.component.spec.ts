import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { AccordionModule } from 'ngx-bootstrap/accordion';
import { ModalModule } from 'ngx-bootstrap/modal';

import { ItemComponent } from './item.component';
import { ModalComponent } from '../../../modal/modal.component';
import { AccordionComponent } from '../accordion.component';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';
import { appConfigProviders } from '../../../common/config';
import { CommentModalComponent } from '../../../comment-modal/comment-modal.component';
import { AddTaskFormComponent } from '../../../add-task-form/add-task-form.component';
import { DropdownFilterComponent } from '../../../filter/dropdown-filter/dropdown-filter.component';
import { ToastrModule } from 'ngx-toastr';
import { RouterTestingModule } from '@angular/router/testing';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { TasksService } from '../../../common/tasks.service';
import { UserService } from '../../../../common/services/user.service';
import { HttpClientModule } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Task } from '../../../common/task';
import { User } from '../../../../common/models/user';

describe('ItemComponent', () => {
  let component: ItemComponent;
  let fixture: ComponentFixture<ItemComponent>;
  let tasksService: Partial<TasksService>;
  let userService: Partial<UserService>;
  const tasksServiceMock = {
    getUserTasks: () => { }
  };

  const userServiceMock = jasmine.createSpyObj('UserService', {
    getAll: Observable.empty(),
    getUserType: '',
    getUserId: '',
    getUser: Observable.empty(),
    getAllHr: Observable.empty(),
  });
  userServiceMock.takeUser = Observable.empty();

  beforeEach(async(() => {
    // tslint:disable-next-line: no-floating-promises
    TestBed.configureTestingModule({
      imports: [
        AccordionModule.forRoot(),
        ModalModule.forRoot(),
        ReactiveFormsModule,
        FormsModule,
        HttpClientTestingModule,
        RouterTestingModule,
        HttpClientModule,
        ToastrModule.forRoot(),
      ],
      declarations: [
        ModalComponent,
        AccordionComponent,
        ItemComponent,
        AddTaskFormComponent,
        DropdownFilterComponent,
        CommentModalComponent
      ],
      providers: [appConfigProviders,
        { provide: TasksService, useValue: tasksServiceMock },
        { provide: UserService, useValue: userServiceMock },
        RouterTestingModule,
      ]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ItemComponent);
    component = fixture.componentInstance;
    component.task = new Task();
    tasksService = fixture.debugElement.injector.get(TasksService);
    userService = TestBed.get(UserService);
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
