import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { throwError, Observable } from 'rxjs';
import { api } from '../../../environments/environment';

@Injectable()
export class AuthService {
  constructor(private readonly http: HttpClient) { }

  auth(login: string, password: string): Observable<object> {
    return this.http.post(`${api}auth/login`, {
      login,
      password
    })
      .catch(this.handleError);
  }

  logout(): any {
    localStorage.clear();
  }

  getUser(): any {
    return localStorage.getItem('type');
  }

  getToken(): any {
    return localStorage.getItem('token');
  }

  isLoggedIn(): boolean {
    return this.getUser() !== null;
  }

  handleError(err: Response | any): any {
    return throwError(err);
  }
}


export const AUTH_PROVIDERS: Array<any> = [
  { provide: AuthService, useClass: AuthService }
];
