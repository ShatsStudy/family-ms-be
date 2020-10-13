import { Pipe, PipeTransform } from '@angular/core';
import { Filter } from './common/filter';
import { Task } from './common/task';
import { FilterByPipeService } from './common/filter-by-pipe.service';

@Pipe({
  name: 'filterTasksBy'
})
export class FilterTasksByPipe implements PipeTransform {
  constructor(
    private readonly filterByPipeService: FilterByPipeService
  ) {}

  transform(tasks: Task[], filters?: Filter[]): Task[] {
    if (!filters || !tasks) {
      return tasks;
    }

    if (this.filterByPipeService.isAllFiltersTurnedOff(filters)) {
      return tasks.filter(task => !(task.resolvedByAuthor && task.resolvedByPerformer));
    }

    return tasks.filter(task => this.filterByPipeService.isTaskMatchesFilters(task, filters));
  }
}
