import { Component, OnInit, Input } from '@angular/core';

@Component({
  selector: 'app-user-image',
  templateUrl: './user-image.component.html',
  styleUrls: ['./user-image.component.scss']
})
export class UserImageComponent implements OnInit {
  @Input() imageURL: string;

  ngOnInit(): void {
    this.imageURL = this.imageURL || 'assets/img/userimg.jpg';
  }

}
