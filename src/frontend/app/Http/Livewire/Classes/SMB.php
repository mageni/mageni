<?php

namespace App\Http\Livewire\Classes;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * Create SMB Credential
 */
class SMB
{
    protected $request;
    public $get_smb_id;

    /**
     * @param $name
     * @param $description
     * @param $login
     * @param $password
     */
    public function create($description, $login, $password)
    {
        $name = Str::uuid();

        /**
         * Create Port List
         */
        $this->request = "<create_credential>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<login>$login</login>";
        $this->request .= "<password>$password</password>";
        $this->request .= "<type>up</type>";
        $this->request .= "</create_credential>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing SMB Credential Creation');

        return $this->get_smb_id = $socket->createSMB($this->request);
    }

    /**
     * @param $name
     * @param $description
     * @param $login
     * @param $password
     */
    public function modify($id, $description, $login, $password)
    {
        $name = Str::uuid();

        /**
         * Create Port List
         */
        $this->request = "<modify_credential credential_id='$id'>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<login>$login</login>";
        $this->request .= "<password>$password</password>";
        $this->request .= "</modify_credential>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing SMB Credential Modification');

        return $this->get_smb_id = $socket->modifySMB($this->request, $id);
    }
}
