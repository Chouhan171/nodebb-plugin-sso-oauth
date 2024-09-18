'use strict';

define('admin/plugins/aad-sso', ['settings', 'alerts'], function (Settings, alerts) {
	var ACP = {};

	ACP.init = function () {
		Settings.load('aad-sso', $('.aad-sso-settings'));

		$('#save').on('click', function () {
			Settings.save('aad-sso', $('.aad-sso-settings'), function () {
				alerts.alert({
					type: 'success',
					alert_id: 'aad-sso-saved',
					title: 'Settings Saved',
					message: 'Please rebuild and restart your NodeBB to apply these settings, or click on this alert to do so.',
					clickfn: function () {
						socket.emit('admin.reload');
					},
				});
			});
		});

		$('a[data-action="help-credentials"]').on('click', function () {
			bootbox.alert({
				title: 'Where is the Credentials page?',
				message: '<img src="' + config.relative_path + '/plugins/nodebb-plugin-aad-sso/images/credentials.png" />',
			});
			return false;
		});
	};

	return ACP;
});
