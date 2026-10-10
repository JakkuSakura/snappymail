<?php

/**
 * Keycloak SSO login for SnappyMail.
 *
 * Flow:
 *   /?KeycloakLogin            -> redirect to Keycloak (authorization code)
 *   /?KeycloakLogin&code=...   -> exchange code, resolve email, mint an SSO hash
 *                              -> redirect to /?Sso&hash=...
 *   clientLogin hook rewrites the minted password into the raw access token and
 *   forces OAUTHBEARER/XOAUTH2 so IMAP/SMTP/Sieve authenticate with the token.
 */
class LoginKeycloakPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Keycloak SSO',
		AUTHOR   = 'JakkuSakura',
		URL      = 'https://github.com/JakkuSakura/snappymail',
		VERSION  = '1.0',
		RELEASE  = '2026-10-10',
		REQUIRED = '2.36.0',
		CATEGORY = 'Login',
		LICENSE  = 'MIT',
		DESCRIPTION = 'IMAP, Sieve & SMTP login using a Keycloak (OIDC) access token via RFC 7628 OAuth2.';

	const TOKENS_PREFIX = ':KCT:';

	public function Init() : void
	{
		$this->UseLangs(true);
		$this->addJs('LoginKeycloak.js');
		$this->addPartHook('KeycloakLogin', 'ServiceKeycloakLogin');
		$this->addHook('imap.before-login', 'clientLogin');
		$this->addHook('smtp.before-login', 'clientLogin');
		$this->addHook('sieve.before-login', 'clientLogin');
	}

	public function configMapping() : array
	{
		return array(
			\RainLoop\Plugins\Property::NewInstance('issuer_url')
				->SetLabel('Issuer URL')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('client_id')
				->SetLabel('Client ID')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('client_secret')
				->SetLabel('Client Secret')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('scope')
				->SetLabel('Scopes')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue('openid email profile'),
			\RainLoop\Plugins\Property::NewInstance('username_domain')
				->SetLabel('Username domain (optional)')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance('button_label')
				->SetLabel('Button label')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDefaultValue('Sign in with Keycloak'),
		);
	}

	public function clientLogin(\RainLoop\Model\Account $oAccount, \MailSo\Net\NetClient $oClient, \MailSo\Net\ConnectSettings $oSettings) : void
	{
		$sPassword = (string) $oSettings->passphrase;
		$iLen = \strlen(self::TOKENS_PREFIX);
		if ($sPassword && self::TOKENS_PREFIX === \substr($sPassword, 0, $iLen)) {
			$aTokens = \json_decode(\substr($sPassword, $iLen), true);
			$sAccessToken = \is_array($aTokens) ? ($aTokens['access_token'] ?? '') : '';
			if ($sAccessToken) {
				$oSettings->passphrase = new \SnappyMail\SensitiveString($sAccessToken);
				\array_unshift($oSettings->SASLMechanisms, 'OAUTHBEARER', 'XOAUTH2');
			}
		}
	}

	public function ServiceKeycloakLogin() : string
	{
		$oActions = \RainLoop\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		$sIssuer   = \rtrim(\trim((string) $this->Config()->Get('plugin', 'issuer_url', '')), '/');
		$sClientId = \trim((string) $this->Config()->Get('plugin', 'client_id', ''));
		$sSecret   = \trim((string) $this->Config()->Get('plugin', 'client_secret', ''));
		$sScope    = \trim((string) $this->Config()->Get('plugin', 'scope', 'openid email profile'));
		$sDomain   = \trim((string) $this->Config()->Get('plugin', 'username_domain', ''));

		if (!$sIssuer || !$sClientId) {
			\header('Content-Type: text/plain; charset=utf-8');
			echo 'Keycloak SSO plugin is not configured.';
			return '';
		}

		$sBase = $oHttp->GetScheme().'://'.$oHttp->GetHost(false).\strtok($oHttp->GetPath(), '?');
		$sRedirect = $sBase.'?KeycloakLogin';

		$sCode  = $_GET['code'] ?? '';
		$sError = $_GET['error'] ?? '';
		if ($sError) {
			\header('Location: '.$sBase.'?KeycloakError='.\urlencode($sError));
			return '';
		}

		if (!$sCode) {
			$sState = \bin2hex(\random_bytes(16));
			\setcookie('kc_sso_state', $sState, array(
				'expires'  => \time() + 600,
				'path'     => '/',
				'secure'   => true,
				'httponly' => true,
				'samesite' => 'Lax',
			));
			\header('Location: '.$sIssuer.'/protocol/openid-connect/auth?'.\http_build_query(array(
				'client_id'     => $sClientId,
				'redirect_uri'  => $sRedirect,
				'response_type' => 'code',
				'scope'         => $sScope,
				'state'         => $sState,
			)));
			return '';
		}

		$sStateOk = isset($_COOKIE['kc_sso_state']) && \hash_equals($_COOKIE['kc_sso_state'], (string) ($_GET['state'] ?? ''));
		if (!$sStateOk) {
			\header('Content-Type: text/plain; charset=utf-8');
			echo 'Invalid SSO state.';
			return '';
		}

		$aToken = \json_decode($this->httpPost($sIssuer.'/protocol/openid-connect/token', array(
			'grant_type'    => 'authorization_code',
			'code'          => $sCode,
			'redirect_uri'  => $sRedirect,
			'client_id'     => $sClientId,
			'client_secret' => $sSecret,
		)), true);

		$sAccessToken = \is_array($aToken) ? ($aToken['access_token'] ?? '') : '';
		$sIdToken     = \is_array($aToken) ? ($aToken['id_token'] ?? '') : '';
		if (!$sAccessToken) {
			\header('Content-Type: text/plain; charset=utf-8');
			echo 'Token exchange failed.';
			return '';
		}

		// The mailbox is resolved from the username claim (which the IdP may map,
		// e.g. a "mail_account" attribute -> preferred_username="jakku"), scoped by
		// username_domain. Falls back to the email claim, then to userinfo.
		$sEmail = '';
		$sUser = $this->claimFromIdToken($sIdToken, 'preferred_username');
		if ($sUser) {
			$sEmail = (false === \strpos($sUser, '@')) ? ($sDomain ? $sUser.'@'.$sDomain : $sUser) : $sUser;
		}
		if (!$sEmail) {
			$sEmail = $this->claimFromIdToken($sIdToken, 'email');
		}
		if (!$sEmail) {
			$aUser = \json_decode($this->httpGet($sIssuer.'/protocol/openid-connect/userinfo', $sAccessToken), true);
			$sEmail = \is_array($aUser) ? ($aUser['email'] ?? '') : '';
			if (!$sEmail && $sDomain) {
				$sU = \is_array($aUser) ? ($aUser['preferred_username'] ?? '') : '';
				if ($sU) {
					$sEmail = false === \strpos($sU, '@') ? $sU.'@'.$sDomain : $sU;
				}
			}
		}
		if (!$sEmail) {
			\header('Content-Type: text/plain; charset=utf-8');
			echo 'Could not resolve email from token.';
			return '';
		}

		$sHash = \RainLoop\Api::CreateUserSsoHash($sEmail, self::TOKENS_PREFIX.\json_encode(array('access_token' => $sAccessToken)));
		if (!$sHash) {
			\header('Content-Type: text/plain; charset=utf-8');
			echo 'Could not create SSO hash.';
			return '';
		}

		\header('Location: '.$sBase.'?Sso&hash='.$sHash);
		return '';
	}

	private function claimFromIdToken(string $sIdToken, string $sClaim) : string
	{
		$aParts = \explode('.', $sIdToken);
		if (\count($aParts) < 2) {
			return '';
		}
		$sPayload = \base64_decode(\strtr($aParts[1], '-_', '+/'));
		$aPayload = \json_decode($sPayload, true);
		$mValue = \is_array($aPayload) ? ($aPayload[$sClaim] ?? '') : '';
		return \is_string($mValue) ? $mValue : '';
	}

	private function httpPost(string $sUrl, array $aFields) : string
	{
		$oCurl = \curl_init($sUrl);
		\curl_setopt_array($oCurl, array(
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => \http_build_query($aFields),
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 20,
			CURLOPT_HTTPHEADER     => array('Content-Type: application/x-www-form-urlencoded'),
		));
		$sResult = \curl_exec($oCurl);
		\curl_close($oCurl);
		return false === $sResult ? '' : $sResult;
	}

	private function httpGet(string $sUrl, string $sBearer) : string
	{
		$oCurl = \curl_init($sUrl);
		\curl_setopt_array($oCurl, array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 20,
			CURLOPT_HTTPHEADER     => array('Authorization: Bearer '.$sBearer),
		));
		$sResult = \curl_exec($oCurl);
		\curl_close($oCurl);
		return false === $sResult ? '' : $sResult;
	}
}
