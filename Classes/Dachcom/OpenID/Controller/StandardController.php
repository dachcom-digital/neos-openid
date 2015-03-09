<?php
namespace Dachcom\OpenID\Controller;

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Error\Message;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Security\Exception\AuthenticationRequiredException;
use TYPO3\Neos\Controller\LoginController;

class StandardController extends LoginController {
    /**
     * @return mixed|void
     */
    public function remoteAction() {
        $authenticationException = NULL;
        try {
            $this->authenticationManager->authenticate();
        } catch (\TYPO3\Flow\Security\Exception\AuthenticationRequiredException $exception) {
            $authenticationException = $exception;
        }

        if ($this->authenticationManager->isAuthenticated()) {
            $storedRequest = $this->securityContext->getInterceptedRequest();
            if ($storedRequest !== NULL) {
                $this->securityContext->setInterceptedRequest(NULL);
            }
            return $this->onAuthenticationSuccess($storedRequest);
        } else {
            $this->onAuthenticationFailure($authenticationException);
            return call_user_func(array($this, $this->errorMethodName));
        }
    }

    /**
     * Is called if authentication was successful.
     *
     * @param ActionRequest $originalRequest The request that was intercepted by the security framework, NULL if there was none
     * @return void
     */
    public function onAuthenticationSuccess(ActionRequest $originalRequest = NULL) {
        if ($this->view instanceof JsonView) {
            $this->view->assign('value', array('success' => $this->authenticationManager->isAuthenticated(), 'csrfToken' => $this->securityContext->getCsrfProtectionToken()));
        } else {
            if ($this->request->hasArgument('lastVisitedNode') && strlen($this->request->getArgument('lastVisitedNode')) > 0) {
                $this->session->putData('lastVisitedNode', $this->request->getArgument('lastVisitedNode'));
            }
            if ($originalRequest !== NULL) {
                // Redirect to the location that redirected to the login form because the user was nog logged in
                $this->redirectToRequest($originalRequest);
            }

            $this->redirect('index', 'Backend\Backend', 'TYPO3.Neos');
        }
    }

    /**
     * Is called if authentication failed.
     *
     * @param AuthenticationRequiredException $exception The exception thrown while the authentication process
     * @return void
     */
    protected function onAuthenticationFailure(AuthenticationRequiredException $exception = NULL) {
        $this->addFlashMessage('The authentication didn\'t complete', 'Wrong credentials', Message::SEVERITY_ERROR, array(), ($exception === NULL ? 1347016771 : $exception->getCode()));
    }
}
