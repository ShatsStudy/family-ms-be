export class OptionPair {
  _id: any;
  readonly name: string;
  constructor(_id: string,
              name: string) {
    this._id = _id;
    this.name = name;
  }
}
