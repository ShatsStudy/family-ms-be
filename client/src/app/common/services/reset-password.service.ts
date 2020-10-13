import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { throwError, Observable } from 'rxjs';
import { api } from '../../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class ResetPasswordService {

  constructor(private readonly http: HttpClient) { }

  sendPassword(newPass: string, token: string): Observable<object> {
    return this.http.post(`${api}auth/recover_password`, {
      newPass,
      token
    })
      .catch(this.handleError);
  }

  handleError(err: Response | any): any {
    return throwError(err);
  }
}
