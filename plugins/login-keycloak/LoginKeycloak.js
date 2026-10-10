(rl => {
	if (!rl) return;
	const label = 'Sign in with Keycloak';
	const inject = () => {
		const box = document.getElementById('plugin-Login-BottomControlGroup');
		if (box && !box.querySelector('.kc-sso')) {
			const a = document.createElement('a');
			a.className = 'btn btn-large kc-sso';
			a.href = '?KeycloakLogin';
			a.textContent = label;
			a.style.cssText = 'display:block;text-align:center;margin:.75rem 0;text-decoration:none';
			box.appendChild(a);
		}
	};
	addEventListener('rl-view-model', e => {
		const vm = e.detail;
		if (vm && 'Login' === vm.viewModelTemplateID) {
			inject();
			setTimeout(inject, 100);
		}
	});
})(window.rl);
