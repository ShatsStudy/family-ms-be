export class TaskStatus {
  constructor(public name?: string,
              public value?: number) {
  }
}

export class TaskType {
  constructor(public name?: string,
              public value?: number) {
  }
}

export class TaskAuthor {
  constructor(public _id?: string,
              public firstName?: string,
              public lastName?: string) {
  }
}

export class Task {
  constructor(public id?: string,
              public name?: string,
              public excerpt?: string,
              public status: TaskStatus = new TaskStatus(),
              public type: TaskType = new TaskType(),
              public date?: string,
              public author: TaskAuthor = new TaskAuthor(),
              public content?: string,
              public assignTo?: string,
              public reassigned?: string,
              public resolvedByAuthor?: boolean,
              public resolvedByPerformer?: boolean,
              public isOpen?: boolean,
              public comments?: any[]) {
  }
}

export class TaskCreateRequestBody {
  constructor(public name?: string,
              public excerpt?: string,
              public statusName?: string,
              public statusValue?: number,
              public typeName?: string,
              public typeValue?: number,
              public author?: string,
              public content?: string,
              public assignTo?: string) {
  }
}

export class TaskEditRequestBody {
  constructor(public id?: string,
              public name?: string,
              public excerpt?: string,
              public status: TaskStatus = new TaskStatus(),
              public author?: string,
              public content?: string,
              public assignTo?: string,
              public reassigned?: string) {
  }
}
