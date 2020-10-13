import {
  Component,
  EventEmitter,
  HostListener,
  Input,
  OnChanges,
  OnInit,
  Output,
  SimpleChanges
} from '@angular/core';
import { OptionPair } from '../../../../common/models/option-pair';
import { UserService } from '../../../../common/services/user.service';

@Component({
  selector: 'app-dropdown-info',
  templateUrl: './dropdown-info.component.html',
  styleUrls: ['./dropdown-info.component.scss']
})
export class DropdownInfoComponent implements OnInit, OnChanges {
  @Input() pairList: OptionPair[];
  @Output() readonly selected = new EventEmitter<any>();
  @Output() readonly selectedRoles = new EventEmitter<any>();
  @Input() required: boolean;
  title: string;
  @Input() positionIdentifier: string;
  @Input() update: string;
  @Input() roles: boolean;
  @Input() updateRolesList: string[];
  selectManagerRole: boolean;
  selectTeamleadRole: boolean;
  rolesList: string[] = [];

  constructor(private readonly userService: UserService) {
  }

  ngOnInit(): void {
    if (!this.update) {
      this.title = 'Choose';
    }
    if (this.positionIdentifier === 'position') {
      if (this.update) {
        this.title = this.update;
      }
      this.userService.chosenDepartment.subscribe(() => {
        this.title = 'Choose';
      });
    }
    if (this.updateRolesList) {
      this.checkTypeOfRoleOnUpdate();
      this.checkRolesForTitle();
    }
  }

  checkTypeOfRoleOnUpdate(): void {
    this.updateRolesList.forEach(elem => {
      if (elem === 'manager') {
        this.selectManagerRole = true;
      } else {
        this.selectTeamleadRole = true;
      }
    });
  }

  setLeftBorderStylesToDropdowns(): string {
    if (this.required) {
      if (this.title === 'Choose') {
        return 'border-red';
      }

      return 'border-green';
    }

    return 'border-blue';
  }

  @HostListener('click') onClick(): void {
    if (this.roles) {
      this.checkRolesForTitle();
    }
  }

  checkRolesForTitle(): void {
    if (this.selectManagerRole && this.selectTeamleadRole) {
      this.title = 'Teamlead & Manager';
    } else if (!this.selectManagerRole && !this.selectTeamleadRole) {
      this.title = 'Choose';
    } else if (this.selectManagerRole) {
      this.title = 'Manager';
    } else {
      this.title = 'Teamlead';
    }
  }

  ngOnChanges(changes: SimpleChanges): void {
    const checkedChangedValues = changes.pairList && changes.pairList.currentValue && changes.pairList.currentValue.length > 0;
    if (checkedChangedValues) {
      const checkIfValueHasCome = changes.pairList.currentValue.find(elem => elem.name === this.update);
      if (this.update && checkIfValueHasCome) {
        this.title = checkIfValueHasCome.name;
      }
    }
    if (changes.update && changes.update.currentValue) {
      if (this.pairList && this.pairList.length > 0) {
        this.title = this.pairList.find(elem => elem.name === this.update).name;
      }
    }
  }

  checkCheckbox(role): void {
    if (role === 'manager') {
      this.selectManagerRole = !this.selectManagerRole;
      this.addRemoveRole(role, this.selectManagerRole);
    } else {
      this.selectTeamleadRole = !this.selectTeamleadRole;
      this.addRemoveRole(role, this.selectTeamleadRole);
    }
    this.selectedRoles.emit(this.rolesList);
  }

  private addRemoveRole(role, selectedRole): void {
    if (selectedRole) {
      this.rolesList.push(role);
    } else {
      this.rolesList = this.rolesList
        .filter(elem => elem !== role);
    }
  }

  selectIt = (pair: OptionPair, event: any) => {
    this.selected.emit(pair._id);
    event.preventDefault();
    if (pair.name) {
      this.title = pair.name;
    }
  };

}
