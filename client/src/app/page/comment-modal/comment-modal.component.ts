import { Component, OnInit, TemplateRef, Input } from '@angular/core';
import { BsModalService, BsModalRef } from 'ngx-bootstrap/modal';
import { Task } from '../common/task';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { TasksService } from '../common/tasks.service';
import { UserService } from '../../common/services/user.service';
import { User } from '../../common/models/user';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-comment-modal',
  templateUrl: './comment-modal.component.html',
  styleUrls: ['./comment-modal.component.scss']
})
export class CommentModalComponent implements OnInit {
  @Input() task: Task;
  user: User;
  modalRef: BsModalRef;
  form: FormGroup;

  constructor(private readonly modalService: BsModalService,
              private readonly tasksService: TasksService,
              private readonly userService: UserService,
              private readonly fb: FormBuilder,
              private readonly toastr: ToastrService) {
    this.form = fb.group({
      comment: ['', Validators.required]
    });
  }

  public openModal(template: TemplateRef<any>): void {
    this.modalRef = this.modalService.show(template);
  }

  public closeModal(): void {
    this.modalRef.hide();
  }

  ngOnInit(): void {
    this.userService.getUser(this.userService.getUserId())
      .subscribe(users => this.user = users);
  }

  createComment(form: any): boolean {
    this.tasksService
      .createComment(this.task.id, form.comment, this.userService.getUserId())
      .subscribe(
        (response: any) => {
          this.toastr.success(response.updated, 'Comment created');
          this.modalRef.hide();
        },
        (error) => {
          this.toastr.error(error.statusText, 'Error response');
        }
      );

    return false;
  }

}
