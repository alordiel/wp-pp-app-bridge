<?php
/**
 * Plugin Name: WordPress - App Bridge for Practice Portuguese
 * Plugin URI:
 * Description: Handles things like login session and etc.
 * Author: Alexander Vasilev
 * Author URI:
 * Version: 0.1
 * Text Domain: pp-app-bridge
 */

defined( 'ABSPATH' ) or exit;

// Require the JWT library
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Hook very early to see if the request is made from the app
 * And create a user session if provided correct creds
 *
 * @return void
 */
function pp_app_login_user(): void {
	$is_app = isset( $_REQUEST['ppapp'] ) && ( $_REQUEST['ppapp'] === 'v1' );
	$tokenExists = isset( $_REQUEST['token'] );
	if ( $is_app && $tokenExists ) {
		$userId = pp_get_user_id_from_token( $_REQUEST['token'] );
		// Login the user that we retrieved from token, if exists
		if ( $userId !== 0) {
			wp_set_current_user( $userId );
			wp_set_auth_cookie( $userId, true, false );
		}
	}
}
add_action('init', 'pp_app_login_user', 5);

/**
 * @param string $token
 *
 * @return int the ID of the user; 0 if no user was found
 */
function pp_get_user_id_from_token( string $token ): int {
	// Get the Secret Key
	$secretKey = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;
	if ( $secretKey ) {
		try {
			// Decode the token
			$token = JWT::decode( $token, new Key( $secretKey, apply_filters( 'jwt_auth_algorithm', 'HS256' ) ) );
			if ( $token->iss === get_bloginfo( 'url' ) ) {
				if ( isset( $token->data->user->id ) ) {
					return (int) $token->data->user->id;
				}
			}
		} catch ( Exception $e ) {
			error_log( $e->getMessage() );
		}
	}

	return 0; // No user where found in the given token
}
