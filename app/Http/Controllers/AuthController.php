<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AuthController extends Controller
{
    /**
     * AuthController constructor.
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = \request(['email', 'password']);

        if (!$token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->responseWithToken($token);
    }

    /**
     * @return mixed
     */
    public function me()
    {
        return response()->json(auth('api'))->user();
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth('api')->logout();
        return response()->json(['message' => 'Success Logout']);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->responseWithToken(auth('api')->refresh());
    }

    /**
     * @param $token
     * @return \Illuminate\Http\JsonResponse
     */
    public function responseWithToken($token)
    {
        return response()->json([
           'access_token' => $token,
            'token_type' => 'bearer',
            'express_in' => auth('api')->factory()->getTTL() * 60,
        ]);
    }
}
