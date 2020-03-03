import { Injectable } from '@angular/core';

import { AuthServerProvider } from '../auth/auth-jwt.service';

@Injectable({ providedIn: 'root' })
export class LoginService {
  constructor(private authServerProvider: AuthServerProvider) {}

  login() {
    this.authServerProvider.login();
  }

  logout() {
    this.authServerProvider.logout();
  }
}
