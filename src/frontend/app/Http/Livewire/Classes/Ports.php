<?php

namespace App\Http\Livewire\Classes;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * Create Custom Ports
 */
class Ports
{
    protected $create_port_list;
    public $get_port_id;

    /**
     * Create Ports
     * @param $name: Name of the Scan
     * @param $description: Description of the Scan
     * @param $ports: Range of the Ports T: for TCP and U: for UDP
     * @return mixed: Port ID
     */
    public function create($ports)
    {
        $name = Str::uuid();

        /**
         * Create Port List
         */
        $this->create_port_list  =  "<create_port_list>";
        $this->create_port_list .=  "<name>$name</name>";
        $this->create_port_list .=  "<comment>$ports</comment>";
        $this->create_port_list .=  "<port_range>$ports</port_range>";
        $this->create_port_list .=  "</create_port_list>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing Ports Creation');

        return $this->get_port_id = $socket->createPorts($this->create_port_list);
    }
}
