import { Component, OnInit } from '@angular/core';

import { LoginService } from 'app/core/login/login.service';
import { AccountService } from 'app/core/auth/account.service';
import { UserService } from 'app/core/user/user.service';
import { Account } from 'app/core/user/account.model';

@Component({
  selector: 'jhi-home',
  templateUrl: './home.component.html',
  styleUrls: ['home.scss']
})
export class HomeComponent implements OnInit {
  account: Account | null = null;
  userList: any;

  constructor(private accountService: AccountService, private loginService: LoginService, private userService: UserService) {}

  ngOnInit(): void {
    this.accountService.identity().subscribe(account => (this.account = account));
    this.userService.query().subscribe(data => (this.userList = data));
  }

  isAuthenticated(): boolean {
    return this.accountService.isAuthenticated();
  }

  login(): void {
    this.loginService.login();
  }
}
