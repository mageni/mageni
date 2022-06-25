<?php

namespace App\Http\Livewire\Notification;

use Livewire\Component;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Http;
use App\Models\Version;
use App\Models\Email as EmailDB;

class Email extends Component
{
    public $version;
    public $emailScanName;
    public $emailAlertTo;
    public $emailAlertURL;
    public $emailAlertEndpoint;

    public function mount(Request $request, $scan, $email)
    {
        $this->emailScanName = $scan;
        $this->emailAlertTo = $email;
        $this->emailAlertEndpoint = "https://www.mageni.net/notifications/email/";
        $this->emailAlertURL = $this->emailAlertEndpoint.$this->emailScanName.'/'.$this->emailAlertTo;

        $this->version = Version::find(1);
        if(!Str::contains($request->header('user-agent'), 'Wget')) {
            Log::info('Invalid GET Request to /notifications/email/');
            abort(404); 
        } else {
            $response = Http::withToken($this->version->api_key)->get($this->emailAlertURL);

            if(Str::contains($response, 'SUCCESS')) {
                Log::info("[SUCCESS] Email Alert Sent " . $scan . ' ' . $email);
            } else {
                Log::error("[FAILURE] sending email alert " . $scan . ' ' . $email);
            }
        }
    }

    public function render()
    {
        return view('livewire.notification.email');
    }
}
