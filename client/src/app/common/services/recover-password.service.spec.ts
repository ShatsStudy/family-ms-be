import { TestBed, async, inject } from '@angular/core/testing';
import { HttpClientModule } from '@angular/common/http';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpTestingController, HttpClientTestingModule } from '@angular/common/http/testing';
import { RecoverPasswordService } from './recover-password.service';
import { api } from '../../../environments/environment';

describe('RecoverPasswordService', () => {
  let httpTestingController: HttpTestingController;
  let service: RecoverPasswordService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ HttpClientModule, ReactiveFormsModule, HttpClientTestingModule ],
      providers: [ RecoverPasswordService ]
    });
    httpTestingController = TestBed.get(HttpTestingController);
    service = TestBed.get(RecoverPasswordService);
  });

  afterEach(() => {
    httpTestingController.verify();
  });

  it('should be created', () => {
    const service: RecoverPasswordService = TestBed.get(RecoverPasswordService);
    expect(service).toBeTruthy();
  });

  it(`should emit 'true' for 200 Ok`, async(inject([RecoverPasswordService, HttpTestingController],
    (service: RecoverPasswordService, backend: HttpTestingController) => {
      service.forgotPassword('gribmail@gmail.com').subscribe((next) => {
        expect(next).toBeTruthy();
      });

      backend.expectOne(`${api}auth/forgot_password`).flush({ status: 200, statusText: 'Send' });
  })));

  it(`should emit 'false' for 404 User not found`, async(inject([RecoverPasswordService, HttpTestingController],
    (service: RecoverPasswordService, backend: HttpTestingController) => {
      service.forgotPassword('gribmail@gmail.com')
      .subscribe(() => {}, err => {
        expect(err).toBe(`User not found`);
      });

      backend.expectOne(`${api}auth/forgot_password`).flush({ status: 404, statusText: 'Not Found' });
  })));
});
