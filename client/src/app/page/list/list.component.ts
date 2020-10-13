import { Component, OnInit, Input } from '@angular/core';

import { Task } from '../common/task';

@Component({
  selector: 'app-list',
  templateUrl: './list.component.html',
  styleUrls: ['./list.component.scss'],
})
export class ListComponent implements OnInit {
  @Input() tasks: Task[];

  ngOnInit(): void {}

}
