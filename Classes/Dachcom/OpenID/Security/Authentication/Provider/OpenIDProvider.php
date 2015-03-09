<?php
namespace Dachcom\OpenID\Security\Authentication\Provider;

use Dachcom\OpenID\Security\Authentication\Token\OpenID;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Authentication\Provider\AbstractProvider;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

class OpenIDProvider extends AbstractProvider {

	/**
	 * @var \TYPO3\Flow\Security\AccountRepository
	 * @Flow\Inject
	 */
	protected $accountRepository;

	/**
	 * @var \Dachcom\OpenID\Security\Service\AuthentificationService
	 * @Flow\Inject
	 */
	protected $authentificationService;

	/**
	 * @var \TYPO3\Flow\Security\Context
	 * @Flow\Inject
	 */
	protected $securityContext;

    /**
     * @var array
     * @Flow\Inject(setting="users")
     */
    protected $users = array();

	/**
	 * Returns the class names of the tokens this provider can authenticate.
	 *
	 * @return array
	 */
	public function getTokenClassNames() {
		return array('Dachcom\OpenID\Security\Authentication\Token\OpenID');
	}

	/**
	 * Checks the given token for validity and sets the token authentication status
	 * accordingly (success, wrong credentials or no credentials given).
	 *
	 * @param \TYPO3\Flow\Security\Authentication\TokenInterface $authenticationToken The token to be authenticated
	 * @return void
	 * @throws \TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException
	 */
	public function authenticate(TokenInterface $authenticationToken) {
		if (!($authenticationToken instanceof OpenID)) {
			throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1217339840);
		}

		/** @var $account \TYPO3\Flow\Security\Account */
		$account = NULL;
        $this->authentificationService->authenticate($authenticationToken);

        $identity = $authenticationToken->getIdentity();

		if (!empty($identity)) {
			$accountRepository = $this->accountRepository;

            $username = '';
            foreach ($this->users as $user) {
                if (rtrim($user['identity'], '/') === rtrim($identity, '/')) {
                    $username = $user['alias'];
                    break;
                }
            }

			$this->securityContext->withoutAuthorizationChecks(function() use ($accountRepository, &$account, $username) {
				$account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($username, 'Typo3BackendProvider');
			});
		}

		if (is_object($account)) {
			if ($authenticationToken->getAuthenticationStatus() === TokenInterface::AUTHENTICATION_SUCCESSFUL) {
				$authenticationToken->setAccount($account);
			} else {
				$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
			}
		} else {
			$authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
		}
	}

}
