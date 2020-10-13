import { async, ComponentFixture, TestBed, fakeAsync, inject } from '@angular/core/testing';
import { CommentModalComponent } from './comment-modal.component';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { RouterTestingModule } from '@angular/router/testing';
import { BsModalService, BsModalRef, ModalModule } from 'ngx-bootstrap/modal';
import { ComponentLoaderFactory } from 'ngx-bootstrap/component-loader';
import { UserService } from '../../common/services/user.service';
import { TasksService } from '../common/tasks.service';
import { ToastrService, ToastrModule } from 'ngx-toastr';
import { DebugElement } from '@angular/core';
import { By } from '@angular/platform-browser';
import { api } from '../../../environments/environment';

describe('CommentModalComponent', () => {
  let component: CommentModalComponent;
  let fixture: ComponentFixture<CommentModalComponent>;
  let de: DebugElement;
  let el: HTMLElement;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [CommentModalComponent],
      imports: [HttpClientTestingModule, FormsModule, RouterTestingModule, ReactiveFormsModule, ModalModule.forRoot(), ToastrModule.forRoot()],
      providers: [BsModalRef, BsModalService, ComponentLoaderFactory, UserService, TasksService, ToastrService]
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(CommentModalComponent);
    component = fixture.componentInstance;
    de = fixture.debugElement.query(By.css('.comment'));
    el = de.nativeElement;
    fixture.detectChanges();
  });

  afterEach(() => {
    const modalService: BsModalService = TestBed.get(BsModalService);
    modalService.hide(1);
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });

  it('should display the `Comment` button', () => {
    expect(el.innerText).toContain('COMMENT');
  });

  it('should display the modal when `Comment` is clicked', () => {
    const createCommentButton = fixture.debugElement.query(By.css('button'));
    spyOn(component, 'openModal').and.callThrough();

    createCommentButton.triggerEventHandler('click', undefined);

    expect(component.openModal).toHaveBeenCalled();
    fixture.detectChanges();
  });

  it(`should emit 'true' for 200 Ok`, async(inject([TasksService, HttpTestingController],
    (service: TasksService, backend: HttpTestingController) => {
      service.createComment('5cefb37c75b240308423ecc5', 'hello', '5cbb6d7ba4908a0db878c37a')
        .subscribe((next) => {
          expect(next)
            .toBeTruthy();
        });

      backend.expectOne(`${api}/issues/comment`)
        .flush({ status: 200, statusText: 'Ok' });
    })));
});
