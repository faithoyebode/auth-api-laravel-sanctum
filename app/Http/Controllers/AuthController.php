<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;

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

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        event(new Registered($user));

        return response()->json([
            'status' => 'success',
            'data' => $response,
            'message' => 'A new user has just been created'
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
        //check if the user has already verified his email
        if($request->user()->hasVerifiedEmail()){
            return response()->json([
                "status" => "error",
                "message" => "Your account has already been verified"
            ], 422);
        }

        $request->user()->sendEmailVerificationNotification();

        return response()->json([
            'status' => 'success',
            'message' => 'A verification link has been sent to your email'
        ], 200);
    }
}
