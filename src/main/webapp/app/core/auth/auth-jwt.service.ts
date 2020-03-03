import { Injectable } from '@angular/core';

import { map, take } from 'rxjs/operators';
import { OidcSecurityService } from 'angular-auth-oidc-client';

@Injectable({ providedIn: 'root' })
export class AuthServerProvider {
  constructor(public oidcSecurityService: OidcSecurityService) {}

  login(): void {
    this.oidcSecurityService.authorize();
  }

  logout(): void {
    this.oidcSecurityService.logoff();
  }

  getToken(): any {
    return this.oidcSecurityService.getIsAuthorized().pipe(
      take(1),
      map(() => this.oidcSecurityService.getToken())
    );
  }
}
