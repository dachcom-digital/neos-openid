<?php
namespace Dachcom\OpenID\Security\Service;

use Dachcom\OpenID\Security\Authentication\Token\OpenID;
use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Mvc\Routing\UriBuilder;
use TYPO3\Flow\Security\Authentication\TokenInterface;

class AuthentificationService {
    /**
     * @param \Dachcom\OpenID\Security\Authentication\Token\OpenID $authenticationToken
     *
     * @throws \TYPO3\Flow\Mvc\Routing\Exception\MissingActionNameException
     * @throws \TYPO3\Flow\Security\Exception\InvalidAuthenticationStatusException
     */
    public function authenticate(OpenID $authenticationToken) {
        $httpRequest = Request::createFromEnvironment();
        $port = (int) $httpRequest->getBaseUri()->getPort();
        if (empty($port) || $port === 80 || $port === 443) {
            $port = '';
        }

        $openid = new \LightOpenID(
            $httpRequest->getBaseUri()->getScheme() . '://' .
            $httpRequest->getBaseUri()->getHost() .
            ($port ? ':' . $port : '')
        );

        $actionRequest = new ActionRequest($httpRequest);

        $uriBuilder = new UriBuilder();
        $uriBuilder->setRequest($actionRequest);
        $uriBuilder->setCreateAbsoluteUri(TRUE);

        if ($openid->mode) {
            if ($openid->validate()) {
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                $authenticationToken->setIdentity($openid->identity);
            }

            return;
        }

        $authUrl = $authenticationToken->getIdentity();
        $authUrl = trim($authUrl);
        $openid->identity = $authUrl;
        $openid->returnUrl = $uriBuilder->uriFor('remote', array(), 'Standard', 'Dachcom.OpenID');

        header('Location: ' . $openid->authUrl());
        exit();
    }
}
