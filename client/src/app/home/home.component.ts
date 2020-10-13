import { Component } from '@angular/core';
import { AuthService } from '../common/services/auth.service';
import { Router } from '@angular/router';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { throwError } from 'rxjs';

import { JwtHelperService } from '@auth0/angular-jwt';


@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss']
})
export class HomeComponent {

  frm: FormGroup;
  hasFailed: boolean;
  showInputErrorslogin = false;
  showInputErrorsPassword = false;

  constructor(private readonly authService: AuthService, public router: Router, private readonly fb: FormBuilder) {
    this.frm = fb.group({
      login: ['', Validators.required],
      password: ['', [Validators.required, Validators.minLength(3)]]
    });
    this.hasFailed = false;
  }

  auth(form: any): boolean {
    const helper = new JwtHelperService();

    this.frm.valueChanges.subscribe((value: string) => {
      if (value.length !== 0) {
        this.hasFailed = false;
      }
    });

    this.authService
      .auth(form.login, form.password)
      .subscribe(
        (response: any) => {
          localStorage.setItem('token', response.token);
          localStorage.setItem('type', helper.decodeToken(response.token).type);
          this.router.navigate(['/profile'])
          .catch(err => throwError(new Error(err)));
        },
        (error) => {
          this.hasFailed = true;
        }
      );

    return false;
  }

}
