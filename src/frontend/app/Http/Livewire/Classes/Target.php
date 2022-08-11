<?php

namespace App\Http\Livewire\Classes;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * Create Target
 */
class Target
{
    public $get_target_id;
    private $create_asset;
    private $request;

    /**
     * Create Target
     * @param $name
     * @param $description
     * @param $targets
     * @param $ports
     * @param $alive
     * @param null $exclude
     * @param null $port_list
     * @param null $ssh_cred
     * @param null $ssh_port
     * @param null $smb_cred
     * @param null $esxi_cred
     * @param null $snmp_cred
     * @return mixed Target ID
     */
    public function create($description, $targets, $ports, $alive, $exclude = null, $port_list = null, $ssh_cred = null, $ssh_port = null, $smb_cred = null)
    {
        $name = Str::uuid();

        /**
         * Create Target
         */
        $this->request = "<create_target>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<hosts>$targets</hosts>";
        $this->request .= "<alive_tests>$alive</alive_tests>";
        $this->request .= isset($exclude) ? "<exclude_hosts>$exclude</exclude_hosts>" : '';
        $this->request .= isset($port_list) ? "<port_list id='$port_list'></port_list>" : "<port_list id='$ports'></port_list>";
        $this->request .= isset($ssh_cred) ? "<ssh_credential id='$ssh_cred'><port>$ssh_port</port></ssh_credential>" : '';
        $this->request .= isset($smb_cred) ? "<smb_credential id='$smb_cred'></smb_credential>" : '';
        $this->request .= "</create_target>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing Asset Creation');

        return $this->get_target_id = $socket->createAsset($this->request);
    }

    /**
     * Modify Target
     * @param $id
     * @param $description
     * @param $targets
     * @param $ports
     * @param $alive
     * @param null $exclude
     * @param null $port_list
     * @param null $ssh_cred
     * @param null $ssh_port
     * @param null $smb_cred
     * @param null $esxi_cred
     * @param null $snmp_cred
     * @return bool|mixed|string
     */
    public function modify($id, $description, $targets, $ports, $alive, $exclude = null, $port_list = null, $ssh_cred = null, $ssh_port = null, $smb_cred = null)
    {
        $name = Str::uuid();

        /**
         * Create Target
         */
        $this->request = "<modify_target target_id='$id'>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<hosts>$targets</hosts>";
        $this->request .= "<alive_tests>$alive</alive_tests>";
        $this->request .= isset($exclude) ? "<exclude_hosts>$exclude</exclude_hosts>" : '';
        $this->request .= isset($port_list) ? "<port_list id='$port_list'></port_list>" : "<port_list id='$ports'></port_list>";
        $this->request .= isset($ssh_cred) ? "<ssh_credential id='$ssh_cred'><port>$ssh_port</port></ssh_credential>" : '';
        $this->request .= isset($smb_cred) ? "<smb_credential id='$smb_cred'></smb_credential>" : '';
        $this->request .= "</modify_target>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing Asset Modification');

        return $this->get_target_id = $socket->modifyAsset($this->request, $id);
    }
}
