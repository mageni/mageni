<?php

namespace App\Rules;

use Illuminate\Contracts\Validation\Rule;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class ValidateSSHKey implements Rule
{
    public $error_message;

    /**
     * Create a new rule instance.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }

    /**
     * Determine if the validation rule passes.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     * @return bool
     */
    public function passes($attribute, $value)
    {
        Log::info('Processing SSH Key Validation');

        if(empty($value)) {
            Log::info('SSH Key must not be empty');
            $this->error_message = "SSH Key must not be empty";
            return false;
        }elseif(!is_string($value)) {
            Log::info('SSH Key must be a string');
            $this->error_message = "SSH Key must be string";
            return false;
        }elseif(!Str::contains($value, '-----BEGIN EC PRIVATE KEY-----') || !Str::contains($value, '-----END EC PRIVATE KEY-----')){
            $this->error_message = "SSH Key is not ECDSA";
            Log::info('SSH Key is EC');
            return false;
        }elseif(!Str::contains($value, 'Proc-Type: 4,ENCRYPTED')){
            $this->error_message = "SSH Key is not encrypted";
            Log::info('SSH Key is not EC');
            return false;
        }elseif (strlen($value) > 1024){
            Log::info('ECDSA Key size is larger than 1024');
            $this->error_message = "ECDSA Key size is larger than 1024";
            return false;
        }elseif(!Str::contains($value, 'Proc-Type: 4,ENCRYPTED')){
            $this->error_message = "SSH Key is not encrypted";
            Log::info('SSH Key is EC');
            return false;
        }elseif(!Str::contains($value, 'DEK-Info')){
            $this->error_message = "SSH Key does not have DEK-Info";
            Log::info('SSH Key does not have DEK-Info');
            return false;
        }

        Log::info('[SUCCESS] SSH Key Validated');

        return $value;
    }

    /**
     * Get the validation error message.
     *
     * @return string
     */
    public function message()
    {
        return $this->error_message;
    }
}
