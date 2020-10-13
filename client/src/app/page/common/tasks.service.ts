import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { BehaviorSubject } from 'rxjs/BehaviorSubject';
import { tap } from 'rxjs/operators';
import { Task, TaskCreateRequestBody, TaskEditRequestBody } from './task';
import { httpOptions } from '../../common/services/user.service';
import { api } from '../../../environments/environment';

@Injectable({
  providedIn: 'root'
})

export class TasksService {
  constructor(private readonly http: HttpClient) { }
  tasks: Task[];

  public takeUserTasks: BehaviorSubject<Task[]> = new BehaviorSubject([]);

  public openTaskById(isOpenID: string): void {
    this.tasks.map(task => {
      task.isOpen = task.id === isOpenID;

      return task;
    });

    this.takeUserTasks.next(this.tasks);
  }

  public taskIsWatched(id: string, issueID: string): Observable < Task > {
    const body = {
      issueID,
      id
    };

    return this.http.put<Task>(`${api}/users/watched_issues`, body, httpOptions);
  }

  public getUserTasks(id: string): Observable < Task[] > {
    return this.http.get<Task[]>(`${api}issues?userId=${id}`, httpOptions)
      .pipe(tap(res => {
        this.tasks = res.map((item: any) =>
          ({
            id: item._id,
            name: item.name,
            excerpt: item.excerpt,
            status: { name: item.status.name, value: item.status.value },
            type: { name: item.type.name, value: item.type.value },
            date: item.date,
            author: item.author,
            content: item.content,
            commentContent: item.commentContent,
            assignTo: item.assignTo,
            reassigned: item.reassigned,
            resolvedByAuthor: !!item.resolvedByAuthor,
            resolvedByPerformer: !!item.resolvedByPerformer,
            isOpen: false,
            comments: item.comments
          })
        )
          .sort((a, b) => (a.date < b.date) ? 1 : ((b.date < a.date) ? -1 : 0));
        this.takeUserTasks.next(this.tasks);
      }));
  }

  public updateResolvedBy(userId: string, taskId: string): Observable < any > {
    const body = {
      userId,
      id: taskId,
    };

    return this.http.put<Task>(`${api}/issues/resolve`, body, httpOptions);
  }

  public createComment(id: string, content: string, creator: string): Observable<any> {
    const body = {
      id,
      content,
      creator
    };

    return this.http.put<Task>(`${api}/issues/comment`, body);
  }

  public editTask(requestBody: TaskEditRequestBody): Observable<any> {

    return this.http.put<TaskEditRequestBody>(`${api}/issues`, requestBody, httpOptions);
  }

  public createTask(requestBody: TaskCreateRequestBody): Observable < any > {
    return this.http.post<TaskCreateRequestBody>(`${api}issues`, requestBody, httpOptions);
  }

  public deleteTask(taskId: string): Observable < {} > {
    return this.http.delete(`${api}issues/${taskId}`, httpOptions);
  }

}
