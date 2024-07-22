<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\User;
use App\UserProfile;
use App\UserSocial;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;
use Validator;

class SocialLoginController extends Controller
{

    public function __construct()
    {
        auth()->setDefaultDriver('api');
        $this->middleware('auth:api', ['except' => ['social_login']]);
    }

    public function social_login(Request $request, $platform)
    {
        $rules = array(
            'social_id' => 'required',
            'username' => 'required',
            'email' => 'required|email',
            //'profile_picture' => 'required',
        );
        $messages = array(
            'social_id.required' => 'Social id is required.',
            'username.required' => 'Username already registered.',
            'email.required' => 'Email is required.',
            //'profile_picture.required' => 'Profile Picture is required.',
        );

        $validator = Validator::make($request->all(), $rules, $messages);
        if ($validator->fails()) {
            $message = $validator->messages()->first();

            $to_return = [];
            $to_return['status'] = 'error';
            $to_return['message'] = $message;

            return response()->json($to_return);
        }

        $input = $request->all();

        $local_user = User::with(['profile', 'social'])->where('email', $request->email)->get()->first();

        if (is_null($local_user)) {
            $new_user = new User();
            $new_user->email = $request->input('email');
            $new_user->username = $request->input('username');
            $new_user->password = bcrypt('h@p!ty_soc!@l_signup');
            $new_user->save();

            $new_user->roles()->attach(HAPITY_USER_ROLE_ID);

            $profile_picture_name = $this->handle_profile_picture_upload_from_url($request->profile_picture, $new_user->id);

            $new_user_profile = new UserProfile();
            $new_user_profile->user_id = $new_user->id;
            $new_user_profile->email = $new_user->email;
            $new_user_profile->auth_key = md5($new_user->username);
            if (!empty($profile_picture_name)) {
                $new_user_profile->profile_picture = $profile_picture_name;
            }
            $new_user_profile->save();

            $new_user_social = new UserSocial();
            $new_user_social->user_id = $new_user->id;
            $new_user_social->social_id = $request->input('social_id');
            $new_user_social->email = $new_user->email;
            $new_user_social->platform = $platform;
            $new_user_social->save();

            $token = auth()->fromUser($new_user);

            $response = $this->generate_response($new_user->id, $platform, $token, $request->input('social_id'));

        } else {

            $local_user->roles()->attach(HAPITY_USER_ROLE_ID);

            $user_existing_social = UserSocial::where('social_id', $request->input('social_id'))->where('user_id', $local_user->id)->first();

            $user_existing_profile = UserProfile::where('user_id', $local_user->id)->first();
            if (!is_null($user_existing_profile)) {
                $profile_picture_name = $this->handle_profile_picture_upload_from_url($request->profile_picture, $local_user->id);

                if (!empty($profile_picture_name)) {
                    $user_existing_profile->profile_picture = $profile_picture_name;
                }
                $user_existing_profile->save();
            }

            if (is_null($user_existing_social)) {
                $new_user_social = new UserSocial();
                $new_user_social->user_id = $local_user->id;
                $new_user_social->social_id = $request->input('social_id');
                $new_user_social->email = $local_user->email;
                $new_user_social->platform = $platform;
                $new_user_social->save();
            }

            $token = auth()->fromUser($local_user);

            $response = $this->generate_response($local_user->id, $platform, $token, $request->input('social_id'));
        }

        return response()->json($response);
    }

    private function generate_response($user_id, $platform, $token, $social_id)
    {
        $user = User::with(['profile', 'social'])->find($user_id)->toArray();

        $user_social = UserSocial::where('user_id', $user_id)->where('platform', $platform)->first();
        $user_social->social_id = $social_id;
        $user_social->save();

        $response = [];
        $response['status'] = "success";
        $response['user_info']['user_id'] = $user['id'];
        $response['user_info']['profile_picture'] = !empty($user['profile']['profile_picture']) ? asset('images/profile_pictures/' . $user['profile']['profile_picture']) : '';
        $response['user_info']['email'] = $user['email'];
        $response['user_info']['username'] = $user['username'];
        $response['user_info']['login_type'] = $platform;
        $response['user_info']['social_id'] = $social_id;
        $response['user_info']['join_date'] = $user['created_at'];
        $response['user_info']['auth_key'] = $user['profile']['auth_key'];
        $response['user_info']['token'] = $token;

        return $response;
    }

    private function handle_profile_picture_upload_from_url($profile_picture_url, $user_id)
    {
        $image_name = '';
        if (!empty($profile_picture_url)) {
            $image_content = file_get_contents($profile_picture_url);
            $image_name = 'profile_picture_' . $user_id . '.jpg';
            File::put(public_path('images' . DIRECTORY_SEPARATOR . 'profile_pictures' . DIRECTORY_SEPARATOR . $image_name), $image_content);
        }

        return $image_name;
    }

}
