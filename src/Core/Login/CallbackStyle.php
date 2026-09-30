<?php

declare(strict_types=1);

namespace Keyway\Sso\Core\Login;

/**
 * How the identity provider hands control back to us - which is the ONLY thing that decides the
 * `SameSite` attribute of the browser-binding cookie.
 *
 * The distinction is named after the mechanism rather than after the protocol on purpose. It is
 * not "SAML is special": it is that a cross-site POST and a top-level redirect are two different
 * events as far as a browser's cookie policy is concerned, and a future binding (SAML Redirect
 * binding, an OIDC `response_mode=form_post`) has to pick a style, not a protocol name.
 *
 *  - CrossSitePost      - the IdP's page submits a form to our callback from the IdP's origin.
 *                         `SameSite=Lax` cookies are WITHHELD, so binding needs `None`, which
 *                         browsers only accept together with `Secure`, i.e. only over HTTPS.
 *                         This is the SAML HTTP-POST binding.
 *  - TopLevelRedirect   - the IdP answers with a 302 and the browser performs a top-level GET.
 *                         `SameSite=Lax` is sent on exactly this kind of navigation, so binding
 *                         works with the stricter attribute and works on plain HTTP too.
 *                         This is the OIDC authorization code callback.
 */
enum CallbackStyle: string
{
    case CrossSitePost = 'cross_site_post';
    case TopLevelRedirect = 'top_level_redirect';

    /**
     * The `SameSite` value a binding cookie must carry to survive this callback.
     */
    public function sameSite(): string
    {
        return $this === self::CrossSitePost ? 'None' : 'Lax';
    }

    /**
     * True when the browser will refuse the cookie unless it is also marked `Secure`.
     *
     * `SameSite=None` without `Secure` is rejected outright by current Chromium, Firefox and
     * Safari, so on this style "no HTTPS" and "no binding" are the same sentence.
     */
    public function requiresSecureTransport(): bool
    {
        return $this === self::CrossSitePost;
    }
}
