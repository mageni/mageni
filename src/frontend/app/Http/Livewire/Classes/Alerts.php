<?php

namespace App\Http\Livewire\Classes;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * Create Custom Ports
 */
class Alerts
{
    private $request;
    public $get_alert_id;

    public function create($scanName, $emailTo)
    {
        $name = Str::uuid();

        $this->request  = "<create_alert>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$name</comment>";
        $this->request .= "<condition>Always</condition>";
        $this->request .= "<event>Task run status changed<data>Done<name>status</name></data></event>";
        $this->request .= "<method>HTTP GET<data>https://127.0.0.1/notifications/email/$scanName/$emailTo<name>URL</name></data></method>";
        $this->request .= "</create_alert>";

        $socket = new Socket();

        Log::info('Processing Alert Creation');

        return $this->get_alert_id = $socket->createAlert($this->request);
    }

    public function modify($scanName, $emailTo, $id)
    {
        $name = Str::uuid();

        $this->request  = "<modify_alert alert_id='$id'>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$name</comment>";
        $this->request .= "<condition>Always</condition>";
        $this->request .= "<event>Task run status changed<data>Done<name>status</name></data></event>";
        $this->request .= "<method>HTTP GET<data>https://127.0.0.1/notifications/email/$scanName/$emailTo<name>URL</name></data></method>";
        $this->request .= "</modify_alert>";

        $socket = new Socket();
        
        Log::info('Processing Alert Modification');

        // dd($this->request);

        return $this->get_alert_id = $socket->modifyAlert($this->request);
    }
}
