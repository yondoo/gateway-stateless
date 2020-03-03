import { NgModule, APP_INITIALIZER } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { AuthInterceptor } from './blocks/interceptor/auth.interceptor';
import { AuthExpiredInterceptor } from './blocks/interceptor/auth-expired.interceptor';
import { ErrorHandlerInterceptor } from './blocks/interceptor/errorhandler.interceptor';
import { NotificationInterceptor } from './blocks/interceptor/notification.interceptor';

import './vendor';
import { GatewaySharedModule } from 'app/shared/shared.module';
import { GatewayCoreModule } from 'app/core/core.module';
import { GatewayAppRoutingModule } from './app-routing.module';
import { GatewayHomeModule } from './home/home.module';
import { GatewayEntityModule } from './entities/entity.module';
// jhipster-needle-angular-add-module-import JHipster will add new module here
import { MainComponent } from './layouts/main/main.component';
import { NavbarComponent } from './layouts/navbar/navbar.component';
import { FooterComponent } from './layouts/footer/footer.component';
import { PageRibbonComponent } from './layouts/profiles/page-ribbon.component';
import { ActiveMenuDirective } from './layouts/navbar/active-menu.directive';
import { ErrorComponent } from './layouts/error/error.component';
import { AuthModule, ConfigResult, OidcConfigService, OidcSecurityService } from 'angular-auth-oidc-client';
import { SERVER_API_URL, KEYCLOAK_SERVER } from 'app/app.constants';
import { filter, take } from 'rxjs/operators';

export function loadConfig(oidcConfigService: OidcConfigService): any {
  console.log('APP_INITIALIZER STARTING');
  return () => oidcConfigService.load_using_custom_stsServer(`${KEYCLOAK_SERVER}/.well-known/openid-configuration`);
}

@NgModule({
  imports: [
    BrowserModule,
    HttpClientModule,
    GatewaySharedModule,
    GatewayCoreModule,
    GatewayHomeModule,
    // jhipster-needle-angular-add-module JHipster will add new module here
    GatewayEntityModule,
    GatewayAppRoutingModule,
    AuthModule.forRoot()
  ],
  declarations: [MainComponent, NavbarComponent, ErrorComponent, PageRibbonComponent, ActiveMenuDirective, FooterComponent],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthExpiredInterceptor,
      multi: true
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: ErrorHandlerInterceptor,
      multi: true
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: NotificationInterceptor,
      multi: true
    },
    OidcConfigService,
    {
      provide: APP_INITIALIZER,
      useFactory: loadConfig,
      deps: [OidcConfigService],
      multi: true
    }
  ],
  bootstrap: [MainComponent]
})
export class GatewayAppModule {
  constructor(private oidcSecurityService: OidcSecurityService, private oidcConfigService: OidcConfigService) {
    // remove fragment also as redirectUrl MUST NOT include fragment: https://tools.ietf.org/html/rfc6749#section-3.1.2
    const BASE_PATH = SERVER_API_URL ? SERVER_API_URL : window.location.origin + '/';
    const INITIAL_URL = window.location.href;
    this.oidcConfigService.onConfigurationLoaded.subscribe((configResult: ConfigResult) => {
      const openIdConfiguration = {
        stsServer: configResult.customConfig.stsServer,
        redirect_url: BASE_PATH,
        // The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer
        // identified by the iss (issuer) Claim as an audience.
        // The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
        // or if it contains additional audiences not trusted by the Client.
        client_id: 'web_app',
        scope: 'roles jhipster openid',
        response_type: 'code',
        silent_renew: true,
        silent_renew_url: `${BASE_PATH}silent-renew.html`,
        post_logout_redirect_uri: BASE_PATH,
        trigger_authorization_result_event: true,
        log_console_debug_active: true
      };
      this.oidcSecurityService.setupModule(openIdConfiguration, configResult.authWellknownEndpoints);
      this.oidcSecurityService
        .getIsModuleSetup()
        .pipe(
          filter((isModuleSetup: boolean) => isModuleSetup),
          take(1)
        )
        .subscribe((isModuleSetup: boolean) => {
          this.oidcSecurityService.authorizedCallbackWithCode(INITIAL_URL);
        });
    });
  }
}
