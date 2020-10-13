import { async, ComponentFixture, TestBed } from '@angular/core/testing';
import { WrapperComponent } from './wrapper.component';
import { PageComponent } from '../page.component';
import { ListComponent } from '../list/list.component';
import { AccordionComponent } from '../list/accordion/accordion.component';
import { NavbarComponent } from '../navbar/navbar.component';
import { NavbarProfileComponent } from '../navbar/navbar-profile/navbar-profile.component';
import { UserBarInfoComponent } from '../user-bar-info/user-bar-info.component';
import { UserImageComponent } from '../user-bar-info/user-image/user-image.component';
import { LinkToProfileComponent } from '../user-bar-info/link-to-profile/link-to-profile.component';
import { FilterComponent } from '../filter/filter.component';
import { DropdownFilterComponent } from '../filter/dropdown-filter/dropdown-filter.component';
import { FilterTasksByPipe } from '../filter-tasks-by.pipe';
import { ItemComponent } from '../list/accordion/item/item.component';
import { RouterTestingModule } from '@angular/router/testing';
import { BurgerMenuComponent } from '../navbar/burger-menu/burger-menu.component';
import { MenuItemComponent } from '../navbar/burger-menu/menu-item/menu-item.component';
import { UpdateAvatarComponent } from '../create-update-user-page/update-avatar/update-avatar.component';
import { DatepickerComponent } from '../create-update-user-page/create-update-user/create-update-date/datepicker/datepicker.component';
import { DatepickerFilterComponent } from '../filter/datepicker-filter/datepicker-filter.component';
import { AccordionModule, BsDatepickerModule, BsDropdownModule, BsModalService, ModalModule } from 'ngx-bootstrap';
import { CommentModalComponent } from '../comment-modal/comment-modal.component';
import { ModalComponent } from '../modal/modal.component';
import { SocialNetworksComponent } from '../navbar/social-networks/social-networks.component';
import { ReactiveFormsModule, FormsModule } from '@angular/forms';
import { AddTaskFormComponent } from '../add-task-form/add-task-form.component';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { HttpClientModule } from '@angular/common/http';
import { appConfigProviders } from '../common/config';

describe('WrapperComponent', () => {
  let component: WrapperComponent;
  let fixture: ComponentFixture<WrapperComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [
        WrapperComponent,
        AccordionComponent,
        ListComponent,
        NavbarComponent,
        NavbarProfileComponent,
        UserBarInfoComponent,
        UserImageComponent,
        LinkToProfileComponent,
        FilterComponent,
        DropdownFilterComponent,
        FilterTasksByPipe,
        PageComponent,
        ItemComponent,
        BurgerMenuComponent,
        MenuItemComponent,
        UpdateAvatarComponent,
        DatepickerComponent,
        DatepickerFilterComponent,
        CommentModalComponent,
        ModalComponent,
        SocialNetworksComponent,
        AddTaskFormComponent
      ],
      imports: [
                RouterTestingModule,
                AccordionModule.forRoot(),
                ReactiveFormsModule,
                FormsModule,
                BsDatepickerModule.forRoot(),
                BsDropdownModule.forRoot(),
                HttpClientTestingModule,
                HttpClientModule,
                ModalModule.forRoot(),
               ],
      providers: [appConfigProviders]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(WrapperComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component)
      .toBeTruthy();
  });
});
