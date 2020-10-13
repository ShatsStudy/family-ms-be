import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';

import { WrapperComponent } from './wrapper/wrapper.component';
import { MyProfileComponent } from './my-profile/my-profile.component';
import { ContactInfoComponent } from './contact-info/contact-info.component';
import { CreateUpdateUserPageComponent } from './create-update-user-page/create-update-user-page.component';
import { UpcomingDatesComponent } from './upcoming-dates/upcoming-dates.component';

export const routes: Routes = [
  { path: '', redirectTo: 'upcoming-tasks', pathMatch: 'full' },
  { path: 'upcoming-tasks', component: WrapperComponent },
  { path: 'my-profile', component: MyProfileComponent },
  { path: 'my-profile/:id', component: MyProfileComponent },
  { path: 'contact-info', component: ContactInfoComponent },
  { path: 'contact-info/:id', component: ContactInfoComponent },
  { path: 'create-user', component: CreateUpdateUserPageComponent },
  { path: 'edit-user/:id', component: CreateUpdateUserPageComponent },
  { path: 'upcoming-dates', component: UpcomingDatesComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class PageRoutingModule { }
