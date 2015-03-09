<?php
namespace Dachcom\OpenID\Security\Authentication\Token;

use TYPO3\Flow\Annotations as Flow;

/**
 * An authentication token used for simple username and password authentication.
 */
class OpenID extends \TYPO3\Flow\Security\Authentication\Token\AbstractToken {

	/**
	 * The openid identity
	 * @var array
	 * @Flow\Transient
	 */
	protected $credentials = array('identity' => 'dachcom.pip.verisignlabs.com');

	/**
	 * Updates the openid credentials from the POST vars, if the POST parameters
	 * are available. Sets the authentication status to REAUTHENTICATION_NEEDED, if credentials have been sent.
	 *
	 * Note: You need to send the identity in the POST parameters:
	 *       __authentication[TYPO3][Flow][Security][Authentication][Token][OpenID][identity]
	 *
	 * @param \TYPO3\Flow\Mvc\ActionRequest $actionRequest The current action request
	 * @return void
	 */
	public function updateCredentials(\TYPO3\Flow\Mvc\ActionRequest $actionRequest) {
		$httpRequest = $actionRequest->getHttpRequest();
		if ($httpRequest->getMethod() === 'POST') {
            $arguments = $actionRequest->getInternalArguments();
            $identity = \TYPO3\Flow\Reflection\ObjectAccess::getPropertyPath($arguments, '__authentication.TYPO3.Flow.Security.Authentication.Token.OpenID.identity');

            if (!empty($identity)) {
                $this->setIdentity($identity);
                $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
            }
		}

        if ($httpRequest->getMethod() === 'GET') {
            $arguments = $actionRequest->getArguments();
            $claimedId = \TYPO3\Flow\Reflection\ObjectAccess::getPropertyPath($arguments, 'openid_claimed_id');
            $identity = $claimedId ?: \TYPO3\Flow\Reflection\ObjectAccess::getPropertyPath($arguments, 'openid_identity');

            if (empty($identity)) {
                return;
            }

            $this->setIdentity($identity);
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }
	}

    /**
     * @return string
     */
    public function getIdentity() {
        return $this->credentials['identity'];
    }

    /**
     * @param string $identity
     */
    public function setIdentity($identity) {
        $this->credentials['identity'] = $identity;
    }

	/**
	 * Returns a string representation of the token for logging purposes.
	 *
	 * @return string The username credential
	 */
	public function  __toString() {
		return 'Identity: "' . $this->credentials['identity'] . '"';
	}

}
