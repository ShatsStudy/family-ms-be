import { Component, OnDestroy, OnInit, TemplateRef } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { UserService } from '../../common/services/user.service';
import { User } from '../../common/models/user';
import { BsModalService, BsModalRef } from 'ngx-bootstrap/modal';
import { Subject } from 'rxjs';

@Component({
  selector: 'app-my-profile',
  templateUrl: './my-profile.component.html',
  styleUrls: ['./my-profile.component.scss']
})
export class MyProfileComponent implements OnInit, OnDestroy {
  private readonly destroy$ = new Subject<void>();

  modalRef: BsModalRef;
  message: string;

  constructor(private readonly userInfoService: UserService,
    private readonly route: ActivatedRoute,
    private readonly modalService: BsModalService,
    private readonly router: Router) { }

  user: User;
  id: any;

  ngOnInit(): void {
    this.checkIdParam();
  }

  private isHr(): boolean {
    return this.userInfoService.getUserType() === 'parent';
  }

  editUser(): void {
    this.router.navigate(['/profile/edit-user', this.user._id], { relativeTo: this.route });
  }
  openModal(template: TemplateRef<any>): void {
    this.modalRef = this.modalService.show(template, { class: 'modal-sm' });
  }

  confirm(): void {
    this.userInfoService.deleteUser(this.user._id)
      .takeUntil(this.destroy$)
      .subscribe(() =>
        this.router.navigate(['/profile/contact-info'], { relativeTo: this.route }));
    this.modalRef.hide();
  }

  decline(): void {
    this.modalRef.hide();
  }

  private readonly checkIdParam = () => {
    this.id = this.route.snapshot.paramMap.get('id');
    this.loadUser(this.id);
  };

  private getFullName(): string {
    return `${this.user.firstName} ${this.user.lastName}`;
  }

  private readonly loadUser = (id: string) => {
    this.userInfoService.getUser(id, true)
      .subscribe(user => this.user = user);
  };

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

}
