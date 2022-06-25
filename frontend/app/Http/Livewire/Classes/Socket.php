<?php

namespace App\Http\Livewire\Classes;

use Illuminate\Support\Facades\Log;

/**
 * Socket Connection
 */
class Socket
{
    private $au_response_clean = '';
    private $xml_response;
    private $json_encode_xml;
    private $json_decode_xml;
    private $create_stream;
    private $create_data;
    private $create_result;
    private $create_xml_clean;
    private $unixsocket = 'unix:///usr/local/var/run/mageni-sqlite.sock';
    private $authentication = '<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>';
    private $authentication_response = '<authenticate_response status="200" status_text="OK"><role>Admin</role><timezone>UTC</timezone><severity>nist</severity></authenticate_response>';

    public int $success = 0;
    public int $failure = 1;
    public int $statusMustBeNew = 7;
    public int $error400 = 5;
    public int $sshkey = 6;
    public int $refresh = 2;
    public int $isdown = 3;
    public int $isbool = 4;

    public function createScan($data)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process create_task
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 201) 
            {
                Log::info('[SUCCESS] Created Scan ' . $this->json_decode_xml['@attributes']['id']);
                return $this->success;
            } else {
                Log::info('[FAILURE] Creating Scan ');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Creating Scan');
            return $this->isbool;
        }
    }

    public function modifyScan($data, $id = null)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process modify_scan
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 200) {
                Log::info('[SUCCESS] Modified Scan ' . $id);
                return $this->success;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 404) {
                Log::error('[FAILURE] Scan could not be modified');
                return $this->failure;
            } elseif($this->json_decode_xml['@attributes']['status'] == 400 && $this->json_decode_xml['@attributes']['status_text'] == "Status must be New to edit scanner") {
                Log::info('[FAILURE] Error 404 editing scan');
                return $this->statusMustBeNew;
            }
        } elseif(is_null($this->json_decode_xml)) {
            Log::info('[IS_NULL] Modified Scan ' . $id);
            return $this->success;
        } else {
            Log::error('Returned Boolean while Modifying Scan');
            return $this->isbool;
        }
    }

    public function createAsset($data)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process create_target
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 201) 
            {
                Log::info('[SUCCESS] Created Asset ' . $this->json_decode_xml['@attributes']['id']);
                return $this->json_decode_xml['@attributes']['id'];
            } elseif ($this->json_decode_xml['@attributes']['status'] == 400 && $this->json_decode_xml['@attributes']['status'] == "Error in host specification") {
                Log::error('[FAILURE] Error in host specification');
                return $this->error400;
            } else {
                Log::error('[FAILURE] Creating Asset');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Creating Asset' . $this->json_decode_xml);
            return $this->isbool;
        }
    }

    public function modifyAsset($data, $id = null)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process modify_target
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 200) {
                Log::info('[SUCCESS] Asset Modified ' . $id);
                return $id;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 400) {
                Log::alert('[WARNING] Asset Exists Already');
                return $id;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 404) {
                Log::error('[FAILURE] Failed to find asset');
                return $id;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 400 && $this->json_decode_xml['@attributes']['status'] == "Error in host specification") {
                Log::error('[FAILURE] Error in host specification');
                return $this->error400;
            }
        } else {
            Log::error('Returned Boolean while Modifying Asset');
            return $this->isbool;
        }
    }

    public function createSchedule($data)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process create_schedule_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 201) 
            {
                Log::info('[SUCCESS] Created Schedule ' . $this->json_decode_xml['@attributes']['id']);
                return $this->json_decode_xml['@attributes']['id'];
            } else {
                Log::error('[FAILURE] Creating Schedule ');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Modifying Schedule');
            return $this->isbool;
        }
    }

    public function modifySchedule($data, $id = null)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process modify_schedule
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 200) {
                Log::info('[SUCCESS] Schedule Modified ' . $id);
                return $id;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 400 && $this->json_decode_xml['@attributes']['status_text'] === 'Schedule exists already') {
                Log::alert('[WARNING] Schedule Exists Already ' . $id);
                return $id;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 400) {
                Log::error('[FAILURE] Invalid iCalendar ' . $id);
                return $id;
            }
        } else {
            Log::error('Returned Boolean while Modifying Schedule');
            return $this->isbool;
        }
    }

    public function createAlert($data)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        
        /**
         * Process create_port_list_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 201) 
            {
                Log::info('[SUCCESS] Alert Created ' . $this->json_decode_xml['@attributes']['id']);
                return $this->json_decode_xml['@attributes']['id'];
            } else {
                Log::error('[FAILURE] Creating Alert');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Creating Alert');
            return $this->isbool;
        }
    }

    public function modifyAlert($data)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        // Log::info('Creating Alert Log' . $this->xml_response);
        
        /**
         * Process create_port_list_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 200) 
            {
                Log::info('[SUCCESS] Alert Modified');
                return $this->success;
            } else {
                Log::error('[FAILURE] Modifying Alert');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean Modifying Alert');
            return $this->isbool;
        }
    }

    public function createPorts($data)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process create_port_list_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 201) 
            {
                Log::info('[SUCCESS] Port List Created ' . $this->json_decode_xml['@attributes']['id']);
                return $this->json_decode_xml['@attributes']['id'];
            } else {
                Log::error('[FAILURE] Creating Port List');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Creating Port List');
            return $this->isbool;
        }
    }

    public function createSMB($data)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process create_credential_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 201) 
            {
                Log::info('[SUCCESS] SMB Credential Created ' . $this->json_decode_xml['@attributes']['id']);
                return $this->json_decode_xml['@attributes']['id'];
            } else {
                Log::error('[FAILURE] Creating SMB Credential');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Creating SMB Credential');
            return $this->isbool;
        }
    }

    public function modifySMB($data, $id = null)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process modify_credential_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 200) 
            {
                Log::info('[SUCCESS] SMB Credential Modified ' . $id);
                return $id;
            } else {
                Log::error('[FAILURE] Modifying SMB Credential');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Modifying SMB Credential');
            return $this->isbool;
        }
    }

    public function createSSH($data)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process create_credentials_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 201) {
                Log::info('[SUCCESS] SSH Credential Created ' . $this->json_decode_xml['@attributes']['id']);
                return $this->json_decode_xml['@attributes']['id'];
            } elseif($this->json_decode_xml['@attributes']['status'] == 400 && $this->json_decode_xml['@attributes']['status_text'] == "Erroneous Private Key.") {
                Log::info('[FAILURE] Erroneous Private Key');
                return $this->sshkey;
            } else {
                Log::error('[FAILURE] Creating SSH Credential');
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Creating SSH Credential');
            return $this->isbool;
        }
    }

    public function modifySSH($data, $id = null)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process modify_credential_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 200) {
                Log::info('[SUCCESS] SSH Credential Modified ' . $id);
                return $id;
            } elseif($this->json_decode_xml['@attributes']['status'] == 400 && $this->json_decode_xml['@attributes']['status_text'] == "Erroneous Private Key.") {
                Log::info('[FAILURE] Erroneous Private Key');
                return $this->sshkey;
            } else {
                Log::error('[FAILURE] Modifying SSH Credential ' . $id);
                return $id;
            }
        } else {
            Log::error('Returned Boolean while Modifying SSH Credential UUID ' . $id);
            return $this->isbool;
        }
    }

    public function startScan($data, $id)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process start_scan_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 202) {
                Log::info('[SUCCESS] Started Scan UUID ' . $id);
                return $this->success;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 503 && str_contains($this->json_decode_xml['@attributes']['status_text'], 'Scanner loading KBs') ) {
                Log::alert('[MESSAGE] Scanner is refreshing knowledge base. Please wait. ' . $this->json_decode_xml['@attributes']['status_text']);
                return $this->refresh;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 503 && str_contains($this->json_decode_xml['@attributes']['status_text'], 'Service temporarily down') ) {
                Log::error('[FAILURE] Backend is down. Please restart the services ' . $this->json_decode_xml['@attributes']['status_text']);
                return $this->isdown;
            } else {
                Log::error("[FAILURE] Starting Scan UUID " . $id);
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Starting Scan UUID ' . $id);
            return $this->isbool;
        }
    }

    public function stopScan($data, $id)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();

        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process stop_scan_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 202) 
            {
                Log::info('[SUCCESS] Stopped Scan UUID ' . $id);
                return $this->success;
            } else {
                Log::error('[FAILURE] Stopping Scan UUID ' . $id);
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Stopping Scan UUID ' . $id);
            return $this->isbool;
        }
    }

    public function resumeScan($data, $id)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process resume_task_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if ($this->json_decode_xml['@attributes']['status'] == 202) 
            {
                Log::info('[SUCCESS] Restarted Scan UUID ' . $id);
                return $this->success;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 503 && str_contains($this->json_decode_xml['@attributes']['status_text'], 'Scanner loading KBs') ) {
                Log::alert('[MESSAGE] Scanner is refreshing knowledge base. Please wait. ' . $this->json_decode_xml['@attributes']['status_text']);
                return $this->refresh;
            } elseif ($this->json_decode_xml['@attributes']['status'] == 503 && str_contains($this->json_decode_xml['@attributes']['status_text'], 'Service temporarily down') ) {
                Log::error('[MESSAGE] Backend is down. Please restart the services ' . $this->json_decode_xml['@attributes']['status_text']);
                return $this->isdown;
            } else {
                Log::error("[FAILURE] Restarting Scan UUID " . $id);
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Restarting Scan UUID ' . $id);
            return $this->isbool;
        }
    }

    public function deleteScan($data, $id)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process delete_task_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if($this->json_decode_xml['@attributes']['status'] == 200) 
            {
                Log::info('[SUCCESS] Deleted Scan UUID ' . $id);
                return $this->success;
            } else {
                Log::error('[FAILURE] Deleting Scan UUID ' . $id);
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Deleting Scan UUID ' . $id);
            return $this->isbool;
        }
    }

    public function lockScan($data, $id)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process delete_task_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if($this->json_decode_xml['@attributes']['status'] == 200) 
            {
                Log::info('[SUCCESS] Locked Scan UUID ' . $id);
                return $this->success;
            } else {
                Log::error('[FAILURE] Locking Scan UUID ' . $id);
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Locking Scan UUID ' . $id);
            return $this->isbool;
        }
    }

    public function unlockScan($data, $id)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process delete_task_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if($this->json_decode_xml['@attributes']['status'] == 200) 
            {
                Log::info('[SUCCESS] Unlocked Scan UUID ' . $id);
                return $this->success;
            } else {
                Log::error('[FAILURE] Unlocking Scan UUID ' . $id);
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Unlocking Scan UUID ' . $id);
            return $this->isbool;
        }
    }

    public function cloneScan($data, $id)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process create_task_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if($this->json_decode_xml['@attributes']['status'] == 201) 
            {
                Log::info('[SUCCESS] Clone Scan UUID ' . $id);
                return $this->success;
            } else {
                Log::error('[FAILURE] Unlocking Scan UUID ' . $id);
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Cloning Scan UUID ' . $id);
            return $this->isbool;
        }
    }

    public function deleteSchedule($data, $id)
    {
        /**
         * Set Permissions
         */
        $this->setPermissions();
        
        /**
         * Open Socket
         */
        $this->create_stream = stream_socket_client($this->unixsocket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_PERSISTENT);
        
        /**
         * Exit if there is not socket connection
         */
        if(!$this->create_stream) 
        {
            Log::error("No socket connection");
            return 1;
        }
       
        /**
         * Write data to socket
         */
        $this->create_data   =  $this->authentication;
        $this->create_data  .=  $data;
        fwrite($this->create_stream, $this->create_data);
        stream_set_blocking($this->create_stream, false);

        /** 
         * Store Data in create_result and close stream
         */
        while (!feof($this->create_stream)) 
        {
            $this->create_result = stream_get_contents($this->create_stream);
            stream_socket_shutdown($this->create_stream, STREAM_SHUT_WR);
        }

        /**
         * Close Socket Connection
         */
        fclose($this->create_stream);

        /**
         * Process Data
         */
        $this->create_xml_clean = str_replace($this->authentication_response, $this->au_response_clean, $this->create_result);
        $this->xml_response = simplexml_load_string($this->create_xml_clean);
        $this->json_encode_xml = json_encode($this->xml_response);
        $this->json_decode_xml = json_decode($this->json_encode_xml, true);

        /**
         * Process delete_schedule_response
         */
        if(!is_bool($this->json_decode_xml))
        {
            if($this->json_decode_xml['@attributes']['status'] == 200) 
            {
                Log::info('[SUCCESS] Deleted Schedule UUID ' . $id);
                return $this->success;
            } else {
                Log::error('[FAILURE] Deleting Schedule UUID ' . $id);
                return $this->failure;
            }
        } else {
            Log::error('Returned Boolean while Deleting Schedule UUID ' . $id);
            return $this->isbool;
        }
    }

    public function setPermissions()
    {
        /**
        * Set Socket Permissions
        */
        $cmd = "sudo chown www-data:www-data /usr/local/var/run/mageni-sqlite.sock";
        
        system($cmd,$return_value);
        
        ($return_value == 0) or die("returned an error: $cmd");

        /**
         * Set Log Permissions
         */
        $cmd = "sudo chown www-data:www-data /var/www/html/storage/logs/laravel.log";
        
        system($cmd,$return_value);
        
        ($return_value == 0) or die("returned an error: $cmd");

        /**
         * Set SQLite Permissions
         */
        $cmd = "sudo chown www-data:www-data /usr/local/var/lib/mageni/sqlite/sqlite.*";
        
        system($cmd,$return_value);
        
        ($return_value == 0) or die("returned an error: $cmd");
    }

}
