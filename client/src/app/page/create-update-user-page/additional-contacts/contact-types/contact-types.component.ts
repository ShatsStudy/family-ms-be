import { Component, OnInit, EventEmitter, Output, Input } from '@angular/core';

@Component({
  selector: 'app-contact-types',
  templateUrl: './contact-types.component.html',
  styleUrls: ['./contact-types.component.scss']
})
export class ContactTypesComponent implements OnInit {

  @Input() id: string;
  @Output() readonly selectOption = new EventEmitter<object>();

  optionName: string;
  options: Array<string>;

  constructor() {
    this.optionName = 'Select type';
    this.options = ['Telegram', 'Skype'];
  }

  private setOption(name: string): void {
    this.optionName = name;
    this.selectOption.emit({i: this.id, name});
  }

  ngOnInit() {
  }

}
