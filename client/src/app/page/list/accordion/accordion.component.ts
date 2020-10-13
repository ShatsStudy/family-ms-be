import { Component, OnInit, Input } from '@angular/core';
import { Task } from '../../common/task';
import { User } from '../../../common/models/user';

declare const require: any;
const jsPDF = require('jspdf');
require('jspdf-autotable');
@Component({
  selector: 'app-accordion',
  templateUrl: './accordion.component.html',
  styleUrls: ['./accordion.component.scss']
})
export class AccordionComponent implements OnInit {
  @Input() tasks: Task[];

  ngOnInit(): void {
  }

  public downloadPDF(): void {
    console.log(this.tasks);
    const rows = [];
    const cols = this.tasks.map(task => task.name);
    cols.unshift('Field')
    const excerpt = this.tasks.map(task => task.excerpt);
    excerpt.unshift('Excerpt');
    rows.push(excerpt);
    const status = this.tasks.map(task => task.status.name);
    status.unshift('Status');
    rows.push(status);
    const type = this.tasks.map(task => task.type.name);
    type.unshift('Type');
    rows.push(type);
    const author = this.tasks.map(task => `${task.author.firstName} ${task.author.lastName}`);
    author.unshift('Author');
    rows.push(author);
    const doc = new jsPDF();
    doc.autoTable(cols, rows, { startY: 10 });
    doc.save('Tasks_HRMS.pdf');
  }

  trackElement(index: number, task: Task): string {
    const uniqueCode = task.id + task.isOpen.toString();

    return uniqueCode;
  }

}
