import { Component, EventEmitter, Input, OnInit, Output, ElementRef, ViewChild } from '@angular/core';
import { FilterOptions } from '../../common/filter-options';
import { Filter } from '../../common/filter';
import { DateService } from '../../common/date.service';
import { DropDownService } from '../../common/drop-down.service';

@Component({
  selector: 'app-datepicker-filter',
  templateUrl: './datepicker-filter.component.html',
  styleUrls: ['./datepicker-filter.component.scss']
})
export class DatepickerFilterComponent implements OnInit {
  @Input() filterItem: Filter;
  @Input() cssClassName: string;
  @Output() readonly filterVal = new EventEmitter();
  @ViewChild('dropDownWrapper') dropDownWrapperView: ElementRef;
  dateDefault: Date;
  filterResult: any;
  isDropup: boolean;
  titleObj: FilterOptions;
  title: string;
  dropDownPositionClassNames: any;
  choiceReadyFlag: number;
  cancelLinkText: string;

  constructor(private readonly dropDownService: DropDownService,
              private readonly dateService: DateService) { }

  ngOnInit(): void {
    this.cancelLinkText = 'View all dates';
    this.titleObj = this.getTitleObject(this.filterItem.options);
    this.title = this.getTitle(this.titleObj);
    this.dateDefault = this.getDateDefault(this.titleObj.value);
    this.isDropup = false;
    this.getDropDownPositionClassNames();
    this.choiceReadyFlag = 0;
  }

  private get defaultTitle(): string {
    return this.filterItem.options.filter((item: FilterOptions) => item.value === -1)[0].name;
  }

  private readonly getTitle = (titleObj: any) => {
    if (titleObj.value === -1) {
      return titleObj.name;
    }

    return titleObj.value;
  };

  private readonly getDateDefault = (title: any) => {
    if (this.filterItem.defaultValue === -1) {
      return new Date();
    }

    return this.convertStringToDate(title);
  };

  private readonly getTitleObject = (options: FilterOptions[]): FilterOptions =>
    options.filter((item: FilterOptions) => item.value === this.filterItem.defaultValue)[0];

  private readonly convertStringToDate = (dateStr: string) => {
    const dateParts = dateStr.split('/');

    return new Date(+ dateParts[2], (+ dateParts[1]) - 1, + dateParts[0]);
  };

  cancelFilter = (i: any, event: any): void => {
    this.choiceReadyFlag ++;
    this.filterResult = i;
    this.updateTitle();
    event.preventDefault();
  };

  selectDate = (event) => {
    this.choiceReadyFlag ++;
    this.filterResult = this.dateService.convertDate(event);
    if (this.isCalendarReady()) {
      this.title = this.filterResult;
    }
  };

  private readonly isCalendarReady = (): boolean =>
    (this.choiceReadyFlag - 1) > 0;

  getDropDownPositionClassNames(): void {
    this.dropDownService.checkDropDownElPosition(this.dropDownWrapperView)
      .subscribe(cssClassNames => {
        this.dropDownPositionClassNames = cssClassNames;
    });
  }

  dropDownClosed = () => {
    const val = (this.isCalendarReady()) ? this.filterResult : -1;
    this.filterVal.emit(val);
    this.updateTitle(this.isCalendarReady());
  };

  private readonly updateTitle = (takeDateToTitle: boolean = false): void => {
    this.title = takeDateToTitle ? this.filterResult : this.defaultTitle;
  };

}
