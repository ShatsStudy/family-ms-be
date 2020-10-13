import { Injectable } from '@angular/core';
import { NetworkLink } from './social-network-link';
import { Observable, of } from 'rxjs';
import { LINKS_LIST } from './mock-social-networks-links';

@Injectable({
  providedIn: 'root'
})
export class SocialNetworkService {
  getLinksList(): Observable<NetworkLink[]> {
    return of(LINKS_LIST);
  }
}
