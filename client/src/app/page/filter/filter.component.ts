import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { Filter } from '../common/filter';

@Component({
  selector: 'app-filter',
  templateUrl: './filter.component.html',
  styleUrls: ['./filter.component.scss']
})
export class FilterComponent implements OnInit {
  @Input() filters: Filter[];
  @Input() cssClass: string;
  @Output() readonly getFilter = new EventEmitter();
  obj: {
    filterId: number,
    optionId: any
  };
  cssClassNames: string;

  ngOnInit(): void {
    this.getCssClassNames();
  }

  private readonly getCssClassNames = () => {
    this.cssClassNames = this.cssClass.length ? 'width-100' : '';
    this.cssClassNames += this.filters.length === 1 ? ' popup-to-right' : '';
  };

  sendFilterVal = (i: number, event: any) => {
    this.obj = {
      filterId: i,
      optionId: event
    };
    this.getFilter.emit(this.obj);
  };

}
