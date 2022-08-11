<?php

namespace App\Http\Livewire\Classes;

use Illuminate\Support\Facades\Log;

/**
 * Create Target
 */
class Scan
{
    public $get_create_result;
    public $get_modify_result;
    public $get_delete_result;
    public $get_clone_result;
    public $get_lock_result;
    public $get_unlock_result;
    public $get_resume_result;
    public $get_stop_result;
    public $get_start_result;
    private $request;

    /**
     * Create Scan
     * @param $name
     * @param $description
     * @param $template
     * @param $target
     * @param $ordering
     * @param $maxtests
     * @param $maxhosts
     * @param $scanner
     * @param null $schedule
     * @return bool
     */
    public function create($name, $description, $template, $target, $ordering, $maxtests, $maxhosts, $scanner, $schedule = null, $alert = null): bool
    {
        $this->request = "<create_task>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<alterable>1</alterable>";
        $this->request .= "<config id='$template'/>";
        $this->request .= "<target id='$target'/>";
        $this->request .= "<hosts_ordering>$ordering</hosts_ordering>";
        $this->request .= "<preferences>";
        $this->request .= "<preference>";
        $this->request .= "<scanner_name>max_checks</scanner_name>";
        $this->request .= "<value>$maxtests</value>";
        $this->request .= "</preference>";
        $this->request .= "<preference>";
        $this->request .= "<scanner_name>max_hosts</scanner_name>";
        $this->request .= "<value>$maxhosts</value>";
        $this->request .= "</preference>";
        $this->request .= "</preferences>";
        $this->request .= isset($alert) ? "<alert id='$alert'/>" : '';
        $this->request .= isset($schedule) ? "<schedule id='$schedule'/>" : '';
        $this->request .= "<scanner id='$scanner'/>";
        $this->request .= "</create_task>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing Scan Creation');

        return $this->get_create_result = $socket->createScan($this->request);
    }

    /**
     * Modify Scan
     * @param $name
     * @param $description
     * @param $template
     * @param $target
     * @param $ordering
     * @param $maxtests
     * @param $maxhosts
     * @param $scanner
     * @param null $schedule
     * @return bool
     */
    public function modify($id, $name, $description, $template, $target, $ordering, $maxtests, $maxhosts, $scanner, $schedule = null, $alert = null): bool
    {
        $this->request = "<modify_task task_id='$id'>";
        $this->request .= "<name>$name</name>";
        $this->request .= "<comment>$description</comment>";
        $this->request .= "<alterable>1</alterable>";
        $this->request .= "<config id='$template'/>";
        $this->request .= "<target id='$target'/>";
        $this->request .= "<hosts_ordering>$ordering</hosts_ordering>";
        $this->request .= "<preferences>";
        $this->request .= "<preference>";
        $this->request .= "<scanner_name>max_checks</scanner_name>";
        $this->request .= "<value>$maxtests</value>";
        $this->request .= "</preference>";
        $this->request .= "<preference>";
        $this->request .= "<scanner_name>max_hosts</scanner_name>";
        $this->request .= "<value>$maxhosts</value>";
        $this->request .= "</preference>";
        $this->request .= "</preferences>";
        $this->request .= isset($alert) ? "<alert id='$alert'/>" : '';
        $this->request .= isset($schedule) ? "<schedule id='$schedule'/>" : '';
        $this->request .= "<scanner id='$scanner'/>";
        $this->request .= "</modify_task>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing Scan Modification');

        return $this->get_modify_result = $socket->modifyScan($this->request, $id);
    }

    /**
     * Start Scan
     * @param $id
     * @return bool
     */
    public function start($id)
    {
        $socket = new Socket();

        Log::info('Processing Scan Start');

        $this->request = "<start_task task_id='$id'/>";

        return $this->get_start_result = $socket->startScan($this->request, $id);
    }

    /**
     * Stop Scan
     * @param $id
     * @return bool
     */
    public function stop($id): bool
    {
        $socket = new Socket();

        Log::info('Processing Scan Stop');

        $this->request = "<stop_task task_id='$id'/>";

        return $this->get_stop_result = $socket->stopScan($this->request, $id);
    }

    /**
     * Scan Resume
     * @param $id
     * @return bool
     */
    public function resume($id): bool
    {
        $socket = new Socket();

        Log::info('Processing Scan Resume');

        $this->request = "<resume_task task_id='$id'/>";

        return $this->get_resume_result = $socket->resumeScan($this->request, $id);
    }

    /**
     * Scan Delete
     * @param $id
     * @return bool
     */
    public function delete($id)
    {
        $socket = new Socket();

        Log::info('Processing Scan Deletion');

        $this->request = "<delete_task task_id='$id' ultimate='1'/>";

        return $this->get_delete_result = $socket->deleteScan($this->request, $id);
    }

    /**
     * Scan Archive
     * @param $id
     * @return bool
     */
    public function lock($id)
    {
        $socket = new Socket();

        Log::info('Processing Scan Lock');

        $this->request = "<delete_task task_id='$id'/>";

        return $this->get_lock_result = $socket->lockScan($this->request, $id);
    }

     /**
     * Scan Unarchive
     * @param $id
     * @return bool
     */
    public function unlock($id)
    {
        $socket = new Socket();

        Log::info('Processing Scan Unlock');

        $this->request = "<restore id='$id'/>";

        return $this->get_unlock_result = $socket->unlockScan($this->request, $id);
    }

    /**
     * Scan Unarchive
     * @param $id
     * @return bool
     */
    public function clone($id)
    {
        $socket = new Socket();

        Log::info('Processing Scan Clone');

        $this->request = "<create_task><copy>$id</copy></create_task>";

        return $this->get_clone_result = $socket->cloneScan($this->request, $id);
    }
}
