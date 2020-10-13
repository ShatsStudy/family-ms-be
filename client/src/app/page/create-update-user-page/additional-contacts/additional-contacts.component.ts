import { Component, OnInit, Output, EventEmitter } from '@angular/core';
import { FormBuilder, FormGroup, Validators, FormControl, FormArray } from '@angular/forms';

@Component({
  selector: 'app-additional-contacts',
  templateUrl: './additional-contacts.component.html',
  styleUrls: ['./additional-contacts.component.scss']
})
export class AdditionalContactsComponent implements OnInit {
  addContacts: FormGroup;
  contacts: [];
  contactObject: object;
  isValid: boolean;

  @Output() readonly sendContacts: EventEmitter<[]> = new EventEmitter<[]>();

  constructor(private readonly fb: FormBuilder) {
    this.addContacts = fb.group({
      form_contacts: new FormArray([])
    });
  }

  ngOnInit(): void {
    this.contacts = [];
    this.isValid = true;
  }

  getContacts(): void {
    this.contacts = this.form_contacts.value;
    if (this.form_contacts.status !== 'VALID') {
      this.isValid = false;
    } else {
      this.isValid = true;
      this.sendContacts.emit(this.contacts);
    }
  }

  onSelectedOption(option: object): void {
    this.form_contacts.controls[option['i']].setValue({
      contact_name: option['name'],
      contact_value: ''
    });
  }

  get form_contacts(): FormArray {
    return this.addContacts.get('form_contacts') as FormArray;
  }

  addContact(): boolean {

    this.form_contacts.push(this.fb.group({
      contact_name: new FormControl('', { validators: Validators.required, updateOn: 'blur' }),
      contact_value: new FormControl('', { validators: Validators.required, updateOn: 'blur' })
    }));

    this.getContacts();

    return false;
  }

  removeContact(i: number): void {
    this.form_contacts.removeAt(i);
    this.contacts = this.form_contacts.value;
    this.isValid = true;
    this.sendContacts.emit(this.contacts);
  }

}
