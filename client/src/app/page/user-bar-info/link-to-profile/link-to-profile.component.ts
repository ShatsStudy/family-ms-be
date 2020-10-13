import { Component, Input } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { throwError } from 'rxjs';

@Component({
  selector: 'app-link-to-profile',
  templateUrl: './link-to-profile.component.html',
  styleUrls: ['./link-to-profile.component.scss']
})
export class LinkToProfileComponent {
  @Input() label: string;
  @Input() info: string;

  constructor(private readonly router: Router, private readonly route: ActivatedRoute) {
  }

}
