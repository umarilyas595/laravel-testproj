<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\MetaInfo;
use App\PluginId;
use App\User;
use App\UserProfile;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use JWTAuth;
use Validator;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        auth()->setDefaultDriver('api');
        $this->middleware('auth:api', ['except' => ['login', 'register','validate_key']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {

        $rules = array(
            'password' => 'required',
            'login' => 'required',
        );
        $messages = array(
            'password.required' => 'Password is required.',
            'login.required' => 'Login Id is required.',
        );

        $validator = Validator::make($request->all(), $rules, $messages);
        if ($validator->fails()) {
            $messages = $validator->messages()->all();
            $returnData['status'] = 'failure';
            $returnData['message'] = $messages[0];
            return response()->json($returnData);
        }

        $login = $request->input('login');
        $field = filter_var($login, FILTER_VALIDATE_EMAIL) ? 'email' : 'username';
        $request->merge([$field => $login]);
        $credentials = $request->only($field, 'password');

        if (Auth::attempt($credentials)) {

            $user = User::with('profile')->find(Auth::id());

            if ($token = JWTAuth::fromUser($user)) {
                if(isset($request->meta_info) && !is_null($request->input('meta_info'))){
                    $metainfo = new MetaInfo();
                    $metainfo->meta_info = isset($request->meta_info) && !is_null($request->input('meta_info')) ? json_encode($request->input('meta_info')) : '';
                    $metainfo->endpoint_url =  !is_null($request->fullUrl()) ? $request->fullUrl() : '';
                    $metainfo->broadcast_id =  null;
                    $metainfo->user_id =  $user->id;
                    $metainfo->time_stamp = time();
                    $metainfo->save();
                }

                $userProfile = $user->toArray();
                $user_info = array();
                $user_info['user_id'] = $userProfile['id'];
                $user_info['profile_picture'] = asset('images/profile_pictures/' . $userProfile['profile']['profile_picture']);
                $user_info['email'] = $userProfile['email'];
                $user_info['username'] = $userProfile['username'];
                $user_info['auth_key'] = $userProfile['profile']['auth_key'];
                $user_info['token'] = $token;

                $returnData['status'] = 'success';
                $returnData['user_info'] = $user_info;

                return response()->json($returnData, 200);
            } else {
                return response()->json(['status' => 'failure', 'message' => 'Invalid Credentials'], 401);
            }
        } else {
            return response()->json(['status' => 'failure', 'message' => 'Invalid Credentials'], 401);
        }
    }

    /**
     * Gets the data for signup user.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $rules = array(
            'email' => 'unique:users,email|email|required',
            'username' => 'unique:users,username|required',
            'password' => 'required',
        );
        $validator = Validator::make(Input::all(), $rules);
        if ($validator->fails()) {
            $messages = $validator->errors()->all();
            $response = array(
                'status' => 'failure',
                'message' => $messages[0],
            );
            return response()->json($response);
        } else {

            $username = $request->input('username');
            $email = $request->input('email');
            $password = $request->input('password');
            $profile_picture = $request->input('profile_picture');
            $name = $request->input('name');

            $name = !empty($name) ? $name : ucwords($username);

            //  Saving User Data
            $user = new User();
            $user->name = $name;
            $user->username = $username;
            $user->email = $email;
            $user->password = bcrypt($password);
            $user->save();

            $user->roles()->attach(HAPITY_USER_ROLE_ID);

            //  Upload Profile Picture if Exists
            $imageName = $this->handle_image_file_upload($request);

            //  Saving User Profile
            $profile = new UserProfile();
            $profile->email = $email;
            $profile->auth_key = md5($username);

            if (!empty($imageName)) {
                $profile->profile_picture = $imageName;
            }

            $user->profile()->save($profile);

            //  Logging In User and Make Response Array
            $token = auth()->attempt(['username' => $username, 'password' => $password]);
            $user_info = array();
            $user_info['user_id'] = $user->id;

            if (!empty($profile->profile_picture)) {
                $user_info['profile_picture'] = asset("images/profile_pictures/" . $profile->profile_picture);
            }
            if(isset($request->meta_info) && !is_null($request->input('meta_info'))){
                $metainfo = new MetaInfo();
                $metainfo->meta_info = isset($request->meta_info) && !is_null($request->input('meta_info')) ? json_encode($request->input('meta_info')) : '';
                $metainfo->endpoint_url =  !is_null($request->fullUrl()) ? $request->fullUrl() : '';
                $metainfo->broadcast_id =  null;
                $metainfo->user_id =  $user->id;
                $metainfo->time_stamp = time();
                $metainfo->save();
            }
            $user_info['email'] = $user->email;
            $user_info['username'] = $user->username;
            $user_info['auth_key'] = $profile->auth_key;
            $user_info['token'] = $token;
            $user_info['join_date'] = $user->created_at;

            $email = $user->email;
            $data = array(
                'name' => $user->username,
                'email' => $user->email,
            );
            Mail::send('emails/welcome', ['data' => $data], function ($message) use ($email) {
                $message->to($email,'chris@hapity.com')->subject('Welcome');
            });

            $returnData['status'] = 'success';
            $returnData['user_info'] = $user_info;
            return response()->json($returnData, 200);
        }
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Get the User Profile.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function getUserProfile(Request $request)
    {
        $userProfile = User::with(['profile', 'social', 'roles'])->where('id', Auth::id())->first()->toArray();

        $user_info = array();
        $user_info['user_id'] = $userProfile['id'];

        if (!empty($userProfile['profile']['profile_picture'])) {
            $user_info['profile_picture'] = asset("images/profile_pictures/" . $userProfile['profile']['profile_picture']);
        }

        $user_info['email'] = $userProfile['email'];
        $user_info['username'] = $userProfile['username'];
        $user_info['auth_key'] = $userProfile['profile']['auth_key'];
        $user_info['screen_name'] = $userProfile['profile']['screen_name'];
        $user_info['join_date'] = $userProfile['created_at'];

        $returnData['status'] = 'success';
        $returnData['profile_info'] = $user_info;

        return response()->json($returnData, 200);
    }

    /**
     * Edit User Profile.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function editUserProfile(Request $request)
    {
        //user_id, username, email, token, password, profile_picture

        $user_id = $request->input('user_id');
        if (!is_null($user_id) && !empty($user_id)) {

            $username = $request->input('username');
            $email = $request->input('email');
            $password = $request->input('password');
            $profile_picture = $request->input('profile_picture');

            $user = User::with(['profile', 'social'])->find($user_id);

            $rules = [];

            $user = User::find($user_id);

            if (!is_null($username) && $user->username != $username) {
                $rules['username'] = 'required|unique:users';
            }

            if (!is_null($email) && $user->email != $email) {
                $rules['email'] = 'required|unique:users|email';
            }

            if (!is_null($password)) {
                $rules['password'] = 'required';
            }

            if (!is_null($profile_picture)) {
                $rules['profile_picture'] = 'required';
            }

            $rules['user_id'] = 'required';

            $request->validate($rules);

            if (!empty($username)) {
                $user->username = $username;
            }
            if (!empty($email)) {
                $user->email = $email;
            }
            if (!empty($password)) {
                $user->password = bcrypt($password);
            }
            $user->save();

            $user->roles()->attach(HAPITY_USER_ROLE_ID);

            $user_profile = UserProfile::where('user_id', $user->id)->first();

            $profile_picture_name = $this->handle_image_file_upload($request);

            if (!empty($profile_picture_name)) {
                $user_profile->profile_picture = $profile_picture_name;
                $user_profile->save();
            }

            $user_profile->email = $user->email;
            $user_profile->save();

            $user_info = array();
            $user_info['user_id'] = $user_id;
            $user_info['profile_picture'] = !empty($user_profile->profile_picture) ? asset("images/profile_pictures/" . $user_profile->profile_picture) : '';
            $user_info['email'] = $user_profile->email;
            $user_info['username'] = $user->username;
            $user_info['auth_key'] = $user_profile->auth_key;

            $returnData['status'] = 'success';
            $returnData['profile_info'] = $user_info;

            return response()->json($returnData, 200);
        } else {
            $returnData = [];
            $returnData['status'] = 'failure';
            $returnData['message'] = 'User Id is Required';

        }
    }

    private function handle_base_64_profile_picture($user, $profile_picture)
    {
        $imageName = '';
        if (!empty($profile_picture)) {

            $profile_picture = str_replace('datagea:im/jpeg;base64,', '', $profile_picture);
            $profile_picture = str_replace('data:image/png;base64,', '', $profile_picture);

            $imageName = 'profile_picture_' . $user->id . '.jpg';
            File::put(public_path('images' . DIRECTORY_SEPARATOR . 'profile_pictures' . DIRECTORY_SEPARATOR . $imageName), base64_decode($profile_picture));
        }

        return $imageName;
    }

    private function handle_image_file_upload($request)
    {
        $field_name = 'profile_picture';

        $thumbnail_image = '';
        if ($request->hasFile($field_name)) {
            $file = $request->file($field_name);
            $ext = $file->getClientOriginalExtension();
            $thumbnail_image = md5(time()) . '.' . $ext;
            $path = public_path('images' . DIRECTORY_SEPARATOR . 'profile_pictures' . DIRECTORY_SEPARATOR );

            if (!is_dir($path)) {
                mkdir($path);
            }

            $file->move($path, $thumbnail_image);

            return $thumbnail_image;
        }

        if ($request->has($field_name) && !empty($request->input($field_name)) && !is_null($request->input($field_name))) {
            $thumbnail_image = md5(time()) . '.jpg';
            $path = public_path('images' . DIRECTORY_SEPARATOR . 'profile_pictures' . DIRECTORY_SEPARATOR );

            if (!is_dir($path)) {
                mkdir($path);
            }

            $base_64_data = $request->input($field_name);

            $base_64_data = str_replace('datagea:im/jpeg;base64,', '', $base_64_data);
            $base_64_data = str_replace('data:image/png;base64,', '', $base_64_data);

            File::put($path . $thumbnail_image, base64_decode($base_64_data));

            return $thumbnail_image;
        }

        return $thumbnail_image;
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
        ]);
    }

    public function validate_key(Request $request){
        if((!isset($request['auth_key']) && !isset($request['type']) && !isset($request['url'])) && (empty($request['auth_key']) && empty($request['type']) && empty($request['url']))){
            $response = array(
                'status' => 'failure',
                'message' => "auth_key , type and url field requires ",
            );
            return response()->json($response);
        }
       
        $auth_key = $request['auth_key'];
        $type = $request['type'];
        $url = $request['url'];
        if(isset($auth_key) && isset($type) && ($type=='wordpress'||$type=='joomla'||$type=='drupal'||$type=='custom') && isset($url)){
            
            $userProfile = UserProfile::where('auth_key',$auth_key)->first();
            if(!empty($userProfile) && $userProfile->id > 0){
                    $plugin_ids = PluginId::where('user_id',$userProfile->user_id)->first();
                    if(empty($plugin_ids)){
                        $data = array(
                            'user_id'   =>  $userProfile->user_id,
                            'type'   =>  $type,
                            'url'   =>  $url,
                            'created_at' => Carbon::now(),
                            'updated_at' => Carbon::now()
                        );
                        PluginId::insert($data);
                        $var = 1;
                    }else{
                        $data = array(
                            'type'   =>  $type,
                            'url'   =>  $url,
                            'updated_at' => Carbon::now()
                        );
                        PluginId::where('id',$plugin_ids->id)->update($data);
                        $var = 1;
                    }
            }else{
                $var = 0;
            }
             return response()->json(['status' => 'success', 'message'=>$var], 200);
        }else{
            return response()->json(['status' => 'failure', 'message'=>'invalid parameters'], 200);
        }
    }
}
