<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Str;


class AuthController extends Controller
{   
    /**
     * Creates a new user.
     *
     *  @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request){
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        $response = [
            'user' => $user,
        ];

        event(new Registered($user));

        return response()->json([
            'status' => 'success',
            'data' => $response,
            'message' => 'Your account has just been created. A verification link has been set to your e-mail address. Click on it to activate your account'
        ], 201);
    }



    /**
     * Verify a user email (triggers when user clicks on verification link after sign up).
     *
     *  @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */

    public function verifyEmail(Request $request){
        $userID = $request['id'];

        $user = User::findorFail($userID);

        if ($user->hasVerifiedEmail()) {
            return  response()->json([
                'status' => 'error',
                'message' => 'Your email has been verified before now'
            ], 403);
        }

        if ($user->markEmailAsVerified()) {
            event(new Verified($user));
        }

        return  response()->json([
            'status' => 'success',
            'message' => 'You can now login'
        ], 200);
     }



    /**
     * Log in a user.
     *
     *  @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request){

        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        //Check email
        $user = User::where('email', $fields['email'])->first();

        //Check password
        $isPasswordCorrect = Hash::check($fields['password'], $user->password);

        //Check if the user exists or the password is correct
        if(!$user || !$isPasswordCorrect){
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid credentials'
            ], 401);
        }

        if (!$user->hasVerifiedEmail()) {
            return  response()->json([
                'status' => 'error',
                'message' => 'Unable to login. Your account has not been verified!'
            ], 403);
        }

        //create token
        $token = $user->createToken('myapptoken')->plainTextToken;

        //prepare response
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response()->json([
            'status' => 'success',
            'data' => $response,
            'message' => 'Logged in'
        ], 200);
    }



    /**
     * Log out a user.
     *
     *  @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function logout(Request $request){
        auth()->user()->tokens()->delete();

        return response()->json([
            'status' => 'success',
            'message' => 'Logged out'
        ]);
    }



    /**
     * Re-send email verification token.
     *
     *  @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function resendEmaiVerificationToken(Request $request){
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        //Check email
        $user = User::where('email', $fields['email'])->first();

        //Check password
        $isPasswordCorrect = Hash::check($fields['password'], $user->password);

        //Check if the user exists or the password is correct
        if(!$user || !$isPasswordCorrect){
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid credentials'
            ], 401);
        }

        //check if the user has already verified his email
        if($user->hasVerifiedEmail()){
            return response()->json([
                "status" => "error",
                "message" => "Your account has already been verified"
            ], 422);
        }

        $user->sendEmailVerificationNotification();

        return response()->json([
            'status' => 'success',
            'message' => 'A verification link has been sent to your email'
        ], 200);
    }



    /**
     * Send password reset token.
     *
     *  @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
    **/
    public function sendResetPasswordLink(Request $request){
        $request->validate(['email' => 'required|email']);

        $status = Password::sendResetLink($request->only('email'));

        return $status === Password::RESET_LINK_SENT ?
            response()->json([
                'status' => 'success',
                'message' => __($status)
            ], 200) : 
            response()->json([
                'status' => 'error',
                'message' => __($status)
            ], 500);
    }



    /**
     * Redirect to Reset Password 
     * (get the token from the password reset link and tell the user 
     * to include the token as part of the password.update route request body).
     *
     *  @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
    **/

    public function redirectToResetPassword(Request  $request){
        $token = $request->query('token');

        if(!$token){
            return response()->json([
                "status" => "error",
                "message" => "The request does not contain any token"
            ], 403);
        }

        $url = URL::to('/api/reset-password'); 
        
        return response()->json([
            "status" => "success",
            "data" => [
                "token" => $token
            ],
            "message" => "Get the token in this response and include it as part of a POST request body to the route ${url}"

        ]);
    }
    /**
     * Reset password (as a result of forget).
     *
     *  @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
    **/
    public function resetPassword(Request $request){
        $request->validate([
            "token" => "required",
            "email" => "required|email",
            "password" => "required|min:3|confirmed"
        ]);

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function($user, $password){
                $user->forceFill([
                    'password' => Hash::make($password) 
                ]);

                $user->save();

                event(new PasswordReset($user));
            }
        );

        return $status === Password::PASSWORD_RESET ?
            response()->json([
                'status' => 'success',
                'message' => __($status)
            ], 200) : 
            response()->json([
                'status' => 'error',
                'message' => __($status)
            ], 500);
    }
}
