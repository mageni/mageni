<?php

namespace App\Http\Livewire\Classes;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * Create SSH Credentials Class
 */
class SSH
{
    protected $request;
    protected $read_key;
    public $get_ssh_id;

    /**
     * Create SSH Credential with Username and Password
     * @param $description
     * @param $type
     * @param $login
     * @param $password
     * @return mixed
     */
    public function createup($description, $type, $login, $password)
    {
        $name = Str::uuid();

        /**
         * Create SSH Credential
         */
        $this->request = "<create_credential>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<login>$login</login>";
        $this->request .= "<password>$password</password>";
        $this->request .= "<type>$type</type>";
        $this->request .= "</create_credential>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing SSH Credential UP (Username and Password) Creation');

        return $this->get_ssh_id = $socket->createSSH($this->request);
    }

    /**
     * Modify SSH Credential with Username and Password
     * @param $description
     * @param $type
     * @param $login
     * @param $password
     * @return mixed
     */
    public function modifyup($id, $description, $login, $password)
    {
        $name = Str::uuid();

        /**
         * Create SSH Credential
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

        Log::info('Processing SSH Credential UP (Username and Password) Modification');

        return $this->get_ssh_id = $socket->modifySSH($this->request, $id);
    }

    /**
     * Create SSH Credential with Keys
     * @param $description
     * @param $type
     * @param $login
     * @param $phrase
     * @param $key
     * @return mixed
     */
    public function createuk($description, $type, $login, $phrase, $key)
    {
        $name = Str::uuid();

        $this->request = "<create_credential>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<login>$login</login>";
        $this->request .= "<key>";
        $this->request .= "<phrase>$phrase</phrase>";
        $this->request .= "<private>$key</private>";
        $this->request .= "</key>";
        $this->request .= "<type>$type</type>";
        $this->request .= "</create_credential>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing SSH Credential UK (Username and Key) Creation');

        return $this->get_ssh_id = $socket->createSSH($this->request);
    }

    public function modifyuk($id, $description, $login, $phrase, $key)
    {
        $name = Str::uuid();
        
        $this->request = "<modify_credential credential_id='$id'>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<login>$login</login>";
        $this->request .= "<key>";
        $this->request .= "<phrase>$phrase</phrase>";
        $this->request .= "<private>$key</private>";
        $this->request .= "</key>";
        $this->request .= "</modify_credential>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing SSH Credential UK (Username and Key) Modification');

        return $this->get_ssh_id = $socket->modifySSH($this->request, $id);
    }
}
