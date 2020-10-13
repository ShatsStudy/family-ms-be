import { Component, OnInit } from '@angular/core';
import { SocialNetworkService } from '../../common/social-network.service';
import { NetworkLink } from '../../common/social-network-link';

@Component({
  selector: 'app-social-networks',
  templateUrl: './social-networks.component.html',
  styleUrls: ['./social-networks.component.scss']
})
export class SocialNetworksComponent implements OnInit {
  links: NetworkLink[];
  constructor(private readonly networksService: SocialNetworkService) { }

  ngOnInit(): void {
    this.networksService.getLinksList()
      .subscribe(links => this.links = links);
  }

  trackById(link: any): string {
    return link.id;
  }
}
