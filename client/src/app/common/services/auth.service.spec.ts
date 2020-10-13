import { TestBed, async, inject } from '@angular/core/testing';
import { HttpClientModule } from '@angular/common/http';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { HttpTestingController, HttpClientTestingModule } from '@angular/common/http/testing';
import { api } from '../../../environments/environment';
import { RouterTestingModule } from '@angular/router/testing';
import { AuthService } from './auth.service';
import { throwError } from 'rxjs';

describe('AuthService', () => {
  let httpTestingController: HttpTestingController;
  let service: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientModule, HttpClientTestingModule, FormsModule, RouterTestingModule, ReactiveFormsModule],
      providers: [AuthService]
    });
    httpTestingController = TestBed.get(HttpTestingController);
    service = TestBed.get(AuthService);
  });

  afterEach(() => {
    httpTestingController.verify();
    service = undefined;
    localStorage.removeItem('type');
  });

  it('should be created', () => {
    const service: AuthService = TestBed.get(AuthService);
    expect(service)
      .toBeTruthy();
  });

  it('should get token', () => {
    const mockToken = [
      { token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' }
    ];

    service.auth('asd', '456')
      .subscribe((response) => {
        expect(response)
          .toEqual(mockToken);
      });

    const mockReq = httpTestingController.expectOne(`${api}auth/login`);

    expect(mockReq.request.method)
      .toEqual('POST');
    expect(mockReq.cancelled)
      .toBeFalsy();
    expect(mockReq.request.responseType)
      .toEqual('json');
    mockReq.flush(mockToken);

  });

  it(`should emit 'true' for 200 Ok`, async(inject([AuthService, HttpTestingController],
    (service: AuthService, backend: HttpTestingController) => {
      service.auth('asd', '456')
        .subscribe((next) => {
          expect(next)
            .toBeTruthy();
        });

      backend.expectOne(`${api}auth/login`)
        .flush({ status: 200, statusText: 'Ok' });
    })));

  it(`should emit 'false' for 404 User not found`, async(inject([AuthService, HttpTestingController],
    (service: AuthService, backend: HttpTestingController) => {
      service.auth('das', '456')
        .subscribe(() => { }, err => {
          expect(err)
            .toBe(`User not found`);
        });

      backend.expectOne(`${api}auth/login`)
        .flush({ status: 404, statusText: 'Not Found' });
    })));

  it('should return false from isLoggedIn when there is no token', () => {
    expect(service.isLoggedIn())
      .toBeFalsy();
  });

  it('should return true from isLoggedIn when there is a token', () => {
    localStorage.setItem('type', 'parent');
    expect(service.isLoggedIn())
      .toBeTruthy();
  });
});
