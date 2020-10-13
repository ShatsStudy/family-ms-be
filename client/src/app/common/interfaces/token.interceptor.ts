import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpErrorResponse,
  HttpInterceptor,
  HttpResponse
} from '@angular/common/http';
import { map, catchError } from 'rxjs/operators';
import { AuthService } from '../services/auth.service';
import { Observable } from 'rxjs/Observable';
import { throwError } from 'rxjs';
@Injectable()
export class TokenInterceptor implements HttpInterceptor {
  constructor(public auth: AuthService) { }
  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

    const token: string = localStorage.getItem('token');

    if (token) {
      request = request.clone({ headers: request.headers.set('Authorization', `Bearer ${token}`) });
    }

    request = request.clone({ headers: request.headers.set('Accept', 'application/json') });

    return next.handle(request)
      .pipe(
        map((event: HttpEvent<any>) => event),
        catchError((error: HttpErrorResponse) => {
          let data = {};
          data = {
            reason: error && error.error.reason ? error.error.reason : '',
            status: error.status
          };

          return throwError(error);
        }));
  }
}
