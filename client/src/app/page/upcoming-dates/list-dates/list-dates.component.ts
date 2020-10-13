import { Component, OnInit, Input } from '@angular/core';
import { DatesItem } from '../../common/dates-item';

@Component({
  selector: 'app-list-dates',
  templateUrl: './list-dates.component.html',
  styleUrls: ['./list-dates.component.scss']
})
export class ListDatesComponent implements OnInit {
  @Input() dates: DatesItem[];
  ngOnInit(): void {}
}
