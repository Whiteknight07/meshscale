import { Config, Context, Layer } from 'effect';

export const config = Config.all({
  accountId: Config.String('ACCOUNT_ID'),
  token: Config.Redacted('API_TOKEN'),
  teamDomain: Config.String('TEAM_DOMAIN'),
  audience: Config.String('ACCESS_AUD'),
  ownerEmail: Config.String('OWNER_EMAIL'),
});
export class Settings extends Context.Service<Settings, Config.Success<typeof config>>()(
  'meshscale/Settings',
) {
  static readonly layer = Layer.effect(Settings)(config);
}
