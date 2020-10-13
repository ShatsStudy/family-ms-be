import { Component, OnInit, Input, Output, EventEmitter, ElementRef, ViewChild } from '@angular/core';
import { FilterOptions } from '../../common/filter-options';
import { Filter } from '../../common/filter';
import { DropDownService } from '../../common/drop-down.service';
import { FilterReturnService } from '../../common/filter-return.service';

@Component({
  selector: 'app-dropdown-filter',
  providers: [ FilterReturnService ],
  templateUrl: './dropdown-filter.component.html',
  styleUrls: ['./dropdown-filter.component.scss']
})
export class DropdownFilterComponent implements OnInit {
  @Input() filterItem: Filter;
  @Input() cssClassName: string;
  @Output() readonly filterVal = new EventEmitter();
  @ViewChild('dropDownWrapper') dropDownWrapperView: ElementRef;
  options: FilterOptions[];
  title: string;
  dropDownPositionClassNames: any;

  get filter(): Filter {
    return this.filterReturnService.filterReturn;
  }

  set filter(filter: Filter) {
    this.filterReturnService.filterReturn = filter;
  }

  constructor(
    private readonly dropDownService: DropDownService,
    private readonly filterReturnService: FilterReturnService
    ) {}

  ngOnInit(): void {
    this.filter = this.filterItem;
    this.options = this.filterItem.options;
    this.title = this.filterReturnService.getTitle(this.filterItem);
    this.getDropDownPositionClassNames();
  }

  selectIt = (i, event) => {
    event.preventDefault();
    this.filterVal.emit(i);
    this.filterReturnService.saveFilterReturn(i)
      .subscribe(data => this.title = data);
  };

  getDropDownPositionClassNames(): void {
    this.dropDownService.checkDropDownElPosition(this.dropDownWrapperView)
      .subscribe(cssClassNames => {
        this.dropDownPositionClassNames = cssClassNames;
    });
  }

}
