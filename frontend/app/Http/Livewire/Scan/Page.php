<?php

namespace App\Http\Livewire\Scan;

use App\Models\{
    Alerts as AlertsModel, 
    CredentialsData,
    Reports,
    Results,
    PortLists,
    Schedules,
    Targets,
    TaskAlerts,
    AlertMethodData,
    TargetsLoginData,
    Task,
    Configs,
    Version,
    Credentials,
    TasksPreferences};
use App\Http\Livewire\Traits\{
    Methods,
    Variables,
    MultiStepForm,
    WithBulkActions,
    WithSorting
};
use Livewire\{
  Component,
  WithFileUploads,
  WithPagination
};
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use App\Http\Livewire\Classes\{
    Scan,
    Alerts,
    Schedule,
    SSH,
    Ports,
    SMB,
    Target
};
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use App\Models\Email;

class Page extends Component
{
    use WithFileUploads;
    use WithPagination;
    use WithSorting;
    use AuthorizesRequests;
    use WithBulkActions;
    use Methods;
    use Variables;
    use MultiStepForm;

    public $queryString = ['sortField', 'sortDirection'];

    public $listeners = [
        'scan-created'  => '$refresh',
        'scan-start'    => '$refresh',
        'scan-stop'     => '$refresh',
        'scan-resume'   => '$refresh',
        'scan-deleted'  => '$refresh',
        'scan-modified' => '$refresh',
        'scan-lock'     => '$refresh',
        'scan-unlock'   => '$refresh',
        'scan-clone'    => '$refresh',
    ];

    public $prompt;

    public function mount()
    {
        $this->editing = Task::make(['creation_time' => now()]);
        $this->resetPage();

        $this->endpoint = "https://www.mageni.net/api/v1/token/plan";

        $this->version = Version::select('api_key')->find(1);
        $this->license = $this->version->api_key;
       
        $response = Http::withToken($this->version->api_key)->get($this->endpoint);

        if(Str::contains($response, 'paid')) {
            $this->plan = 'Paid';
            Log::info("You are on the paid plan.");
        } else {
            $this->plan = 'Free';
            Log::info("You are on the free plan.");
        }
    }

    public function hydrate()
    {
        $this->resetCredentials();   
        $this->resetValidation();
        $this->refreshComponent();
    }

    public function updated($propertyName)
    {
        $this->validateOnly($propertyName);
    }

    public function newScanModal()
    {
        $this->authorize('create_scans');

        $this->resetFields();

        $this->modalFormVisible = true;

        $this->stopPolling = 'Yes';
    }

    public function closeShowModal()
    {
        $this->resetFields();

        $this->modalFormVisible = false;

        $this->stopPolling = 'No';
    }

    public function deleteShowModal($taskID)
    {
        $this->authorize('delete_scans');
        $this->taskID = $taskID;
        $this->deleteModalFormVisible = true;
    }

    public function refreshComponent() {
        $this->update = !$this->update;
    }

    public function closeDeleteModalConfirmationForm()
    {
        $this->deleteModalConfirmationFormVisible = false;
    }

    public function closeDeleteShowModal()
    {
        $this->deleteModalFormVisible = false;
    }

    public function scanDetails($id)
    {
        return redirect()->to('/scan/'.$id);
    }

    public function edit($taskID)
    {
        $this->authorize('edit_scans');
        
        $this->resetFields();

        $this->getTask = Task::find($taskID);

        /**
         * General Variables
         */
        $this->scanUUID = $this->getTask->uuid;
        $this->scanID = $this->getTask->id;
        $this->scanName = $this->getTask->name;
        $this->getTarget = $this->getTask->target;
        $this->getConfig = $this->getTask->config;
        $this->getSchedule = $this->getTask->schedule;
        $this->scanDescription = $this->getTask->comment;

        /**
         * Alerts 
         */
        $this->getAlert = TaskAlerts::select('alert')->where('task', $this->scanID)->first();
        if($this->getAlert)
        {
            $this->getAlertURL = AlertMethodData::select('data')
                                ->where('alert', $this->getAlert->alert)
                                ->where('name', 'URL')
                                ->first();

            $this->getAlertID = AlertsModel::select('uuid')->where('id', $this->getAlert->alert)->first();   
            
            $this->getAlertUUID = $this->getAlertID->uuid;   

            $getURLData = parse_url($this->getAlertURL->data);
        
            $path = explode("/", $getURLData['path']);

            $getEmailFromArray = array_diff($path, array("notifications", "email"));

            $this->email = $getEmailFromArray[4];
            $this->hasNotification = 'Yes';
            $this->emailNotification = 'Yes';
        }

        /**
         * Targets Information
         */
        $this->getTargetInfo = Targets::find($this->getTarget);
        $this->targetList = $this->getTargetInfo->hosts;
        $this->targetUUID = $this->getTargetInfo->uuid;
        $this->targetExclude = $this->getTargetInfo->exclude_hosts;
        if($this->targetExclude !== ""){
            $this->toggleExcludeTargets = 'Yes';
        }

        /**
         * Performance Information
         */
        $this->getTaskPrefInfo = TasksPreferences::where('task', '=', $this->scanID)->where('name', 'like', "%max_hosts%")->get();

        foreach ($this->getTaskPrefInfo as $info) {
            if($info->value === '10') {
                $this->scanSpeed = 1;
            }elseif($info->value === '30') {
                $this->scanSpeed = 3;
            } else {
                $this->scanSpeed = 2;
            }
        }

        /**
         * Ports Information
         */
        $this->getPortsInfo = PortLists::find($this->getTargetInfo->port_list);
        $this->getPortsUUID = $this->getPortsInfo->uuid;
        $this->portRange = $this->getPortsInfo->comment;
        if(!empty($this->portRange)) {
            $this->targetPorts = 'customports';
        } else {
            $this->targetPorts = $this->getPortsInfo->uuid;
        }

        /**
         * Host Discovery Method
         */
        $this->targetAlive = $this->getTargetInfo->alive_test;

        /**
         * Configuration Information
         */
        $this->configs = Configs::find($this->getConfig);
        $this->configName = $this->configs->name;
        $this->configUUID = $this->configs->uuid;

        /**
         * Credentials Information
         */
        $this->getTargetLogin = TargetsLoginData::where('target', '=', $this->getTargetInfo->id)->get()->toArray();
        if(isset($this->getTargetLogin)) {
            foreach($this->getTargetLogin as $logins) {
                if(isset($logins['type']) && $logins['type'] === 'ssh')
                {
                    $this->hasSSHCredentials = 'Yes';
                    $this->sshType = Credentials::where('id', '=', $logins['credential'])->get();
                    foreach ($this->sshType as $type) {
                        $this->credentialType = $type->type;
                        $this->credentialSSHID = $type->uuid;
                    }
                    $this->sshPort = $logins['port'];
                    $this->loginCredSSHUser = CredentialsData::where([
                        ['credential', '=', $logins['credential']],
                        ['type', '=', 'username']
                        ])
                        ->get()
                        ->toArray();
                    $this->sshLogin = $this->loginCredSSHUser[0]['value'];
                }

                if(isset($logins['type']) && $logins['type'] === 'smb')
                {
                    $this->hasSMBCredentials = 'Yes';
                    $this->getCredentialSMBID = Credentials::where('id', '=', $logins['credential'])->get()->toArray();
                    $this->credentialSMBID = $this->getCredentialSMBID[0]['uuid'];
                    $this->loginCredSMBUser = CredentialsData::where([
                        ['credential', '=', $logins['credential']],
                        ['type', '=', 'username']
                    ])
                        ->get()
                        ->toArray();
                    $this->smbLogin = $this->loginCredSMBUser[0]['value'];
                }
            }
        } elseif(is_null($this->getTargetLogin)) {
            $this->hasSSHCredentials = 'No';
            $this->hasSMBCredentials = 'No';
            $this->getCredentialSMBID = null;
            $this->credentialSMBID = null;
            $this->loginCredSMBUser = null;
            $this->credentialType = null;
            $this->credentialSSHID = null;
            $this->sshPort = null;
            $this->sshLogin = null;
        }

        /**
         * Schedule Information
         */
        $this->getScheduleInfo = Schedules::find($this->getSchedule);
        if(isset($this->getScheduleInfo)) {
            $this->hasSchedule =  'Yes';
            $this->getScheduleUUID = $this->getScheduleInfo->uuid;
            $this->getScheduleiCal = $this->getScheduleInfo->icalendar;
            $this->getScheduleFT = $this->getScheduleInfo->first_time;
            $this->timezone = $this->getScheduleInfo->timezone;
            date_default_timezone_set($this->timezone);
            $this->scheduleStartDate = date('m/d/Y H:i',$this->getScheduleFT);

            if(str_contains($this->getScheduleiCal, 'DAILY')) {
                $this->scheduleFrequency = 'DAILY';
            }elseif (str_contains($this->getScheduleiCal, 'MO,TU,WE,TH,FR')) {
                $this->scheduleFrequency = 'WORKWEEK';
            }elseif (str_contains($this->getScheduleiCal, 'HOURLY')) {
                $this->scheduleFrequency = 'HOURLY';
            }elseif (str_contains($this->getScheduleiCal, 'MONTHLY')) {
                $this->scheduleFrequency = 'MONTHLY';
            }elseif (str_contains($this->getScheduleiCal, 'WEEKLY')) {
                $this->scheduleFrequency = 'WEEKLY';
            }else {
                if($this->hasSchedule === 'No') {
                    $this->scheduleFrequency = '';
                } else {
                    $this->scheduleFrequency = 'ONCE';
                }
            }
        } elseif(is_null($this->getScheduleInfo)) {
            $this->hasSchedule =  'No';
            $this->scheduleFrequency = null;
            $this->scheduleStartDate = null;
            $this->timezone = null;
            $this->getScheduleFT = null;
            $this->getScheduleiCal = null;
            $this->getScheduleUUID = null;
        }

        $this->showEditModal = true;

        $this->stopPolling = 'Yes';
    }

    public function saveEditScan()
    {
        $this->authorize('edit_scans');

        /**
         * Handle Ports
         */
        if($this->targetPorts === 'fd591a34-56fd-11e1-9f27-406186ea4fc5') {
            $this->created_port_list_id = 'fd591a34-56fd-11e1-9f27-406186ea4fc5';
        } elseif($this->targetPorts === 'ab33f6b0-57f8-11e1-96f5-406186ea4fc5') {
            $this->created_port_list_id = 'ab33f6b0-57f8-11e1-96f5-406186ea4fc5';
        } elseif($this->targetPorts === '730ef368-57e2-11e1-a90f-406186ea4fc5') {
            $this->created_port_list_id = '730ef368-57e2-11e1-a90f-406186ea4fc5';
        } elseif($this->targetPorts === 'customports')
        {
            $ports = new Ports();

            $ports->create($this->portRange);

            $this->created_port_list_id = $ports->get_port_id;
        }

        if($this->toggleNotification === 'Edit' && isset($this->email)) {
            $alert = new Alerts();

            $alert->modify($this->scanName, $this->email, $this->getAlertUUID);

            $this->created_alert_id = $this->getAlertUUID;

        } elseif ($this->toggleNotification === 'Create' && isset($this->email)) {
            $alert = new Alerts();

            $alert->create($this->scanName, $this->email);

            $this->created_alert_id = $alert->get_alert_id;
        } elseif ($this->toggleNotification === 'Remove' && isset($this->email)) {

            $this->created_alert_id = 0;

        }

        /**
         * Handle SSH Credentials
         */
        if($this->toggleSSHCredentials === 'Create')
        {
            $ssh = new SSH();

            if($this->credentialType === 'up') {
                $ssh->createup($this->scanDescription, $this->credentialType, $this->sshLogin, $this->sshPassword);
            } else {
                $ssh->createuk($this->scanDescription, $this->credentialType, $this->sshLogin, $this->sshPhrase, $this->sshKey);
            }
            
            $this->get_created_ssh_credential_id = $ssh->get_ssh_id;

        } elseif ($this->toggleSSHCredentials === 'Edit') {

            $ssh = new SSH();

            if($this->credentialType === 'up') {
                $ssh->modifyup($this->credentialSSHID, $this->scanDescription, $this->sshLogin, $this->sshPassword);
            } elseif ($this->credentialType === 'usk') {
                $ssh->modifyuk($this->credentialSSHID, $this->scanDescription, $this->sshLogin, $this->sshPhrase, $this->sshKey);
            }
            
            $this->get_created_ssh_credential_id = $ssh->get_ssh_id;

        } elseif ($this->toggleSSHCredentials === 'Remove') {
            
            $this->get_created_ssh_credential_id = 0;

        }

        /**
         * Handle SMB Credentials
         */
        if($this->toggleSMBCredentials === 'Create')
        {
            $smb = new SMB();

            $smb->create($this->scanDescription, $this->smbLogin, $this->smbPassword);

            $this->get_created_smb_credential_id = $smb->get_smb_id;

        } elseif ($this->toggleSMBCredentials === 'Edit') {

            $smb = new SMB();

            $smb->modify($this->credentialSMBID, $this->scanDescription, $this->smbLogin, $this->smbPassword);

            $this->get_created_smb_credential_id = $smb->get_smb_id;

        } elseif ($this->toggleSMBCredentials === 'Remove') {

            $this->get_created_smb_credential_id = 0;
            
        }

        /**
         * Handle Schedule
         */
        if($this->toggleSchedule === 'Create')
        {
            $schedule = new Schedule();

            $schedule->create(
                $this->scanDescription, 
                $this->timezone, 
                $this->scheduleStartDate, 
                $this->scheduleFrequency
            );

            $this->get_created_schedule_id = $schedule->get_schedule_id;

        } elseif ($this->toggleSchedule === 'Modify') {

            $schedule = new Schedule();

            $schedule->modify(
                $this->getScheduleUUID, 
                $this->scanDescription, 
                $this->timezone, 
                $this->scheduleStartDate, 
                $this->scheduleFrequency
            );

            $this->get_created_schedule_id = $schedule->get_schedule_id;

        } elseif ($this->toggleSchedule === 'Remove') {
            
            $this->get_created_schedule_id = 0;

        }

        /**
         * Modify Target
         */
        $target = new Target();

        if($this->toggleExcludeTargets === 'No'){

            $this->targetExclude = '';
        
        }

        $target->modify(
            $this->targetUUID,
            $this->scanDescription,
            $this->targetList,
            $this->targetPorts,
            $this->alivetest,
            $this->targetExclude,
            $this->created_port_list_id,
            $this->get_created_ssh_credential_id,
            $this->sshPort,
            $this->get_created_smb_credential_id
        );
    
        $this->created_target_id = $target->get_target_id;

        /**
         * Modify Scan
         */
        $scan = new Scan();

        $scan->modify(
            $this->scanUUID,
            $this->scanName,
            $this->scanDescription,
            $this->configUUID,
            $this->created_target_id,
            $this->hostOrdering,
            $this->maxTests,
            $this->maxHosts,
            $this->scannerUUID,
            $this->get_created_schedule_id,
            $this->created_alert_id
        );
        
        $this->resetFields();
        $this->showEditModal = false;
        $this->currentPage = 1;
        $this->stopPolling = 'No';

        if($scan->get_modify_result == 0) {
            $this->emit('scan-modified', [
                'title'     => 'Scan Modified',
                'icon'      => 'success',
                'timer'     => $this->alertTimer,
                'iconColor' => 'green',
            ]);
        } elseif($scan->get_modify_result == 1) {
            $this->emit('scan-modified', [
                'title'     => 'Scan Modification',
                'icon'      => 'error',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        } elseif($scan->get_modify_result == 7) {
            $this->emit('error-modifying-scan', [
                'title'     => 'Error 404',
                'text'      => 'We are aware of this error and it will be fixed. Meanwhile, as a workaround, please lock the scan and create a new one.',
                'icon'      => 'error',
                'iconColor' => 'red',
            ]);
        }
    }

    public function closeEditModal()
    {
        $this->resetFields();
        
        $this->showEditModal = false;
        
        $this->stopPolling = 'No';
    }

    public function saveCreateScan()
    {
        $this->authorize('create_scans');

        /**
         * Create Custom Ports
         */
        if($this->targetPorts === 'fd591a34-56fd-11e1-9f27-406186ea4fc5') {
            $this->created_port_list_id = 'fd591a34-56fd-11e1-9f27-406186ea4fc5';
        } elseif($this->targetPorts === 'ab33f6b0-57f8-11e1-96f5-406186ea4fc5') {
            $this->created_port_list_id = 'ab33f6b0-57f8-11e1-96f5-406186ea4fc5';
        } elseif($this->targetPorts === '730ef368-57e2-11e1-a90f-406186ea4fc5') {
            $this->created_port_list_id = '730ef368-57e2-11e1-a90f-406186ea4fc5';
        } elseif($this->targetPorts === 'customports')
        {
            $ports = new Ports();

            $ports->create($this->portRange);

            $this->created_port_list_id = $ports->get_port_id;
        }

        if($this->emailNotification === 'Yes')
        {
            $alert = new Alerts();

            $alert->create($this->scanName, $this->emailTo);

            $this->created_alert_id = $alert->get_alert_id;
        }

        /**
         * Create SSH Credentials
         */
        if($this->toggleSSHCredentials === 'Yes')
        {
            $ssh = new SSH();

            if($this->credentialType === 'up') {
                $ssh->createup($this->scanDescription, $this->credentialType, $this->sshLogin, $this->sshPassword);

                $this->get_created_ssh_credential_id = $ssh->get_ssh_id;
            } else {
                $ssh->createuk($this->scanDescription, $this->credentialType, $this->sshLogin, $this->sshPhrase, $this->sshKey);

                $this->get_created_ssh_credential_id = $ssh->get_ssh_id;
            }
        }

        /**
         * Create SMB Credentials
         */
        if($this->toggleSMBCredentials === 'Yes')
        {
            $smb = new SMB();

            $smb->create($this->scanDescription, $this->smbLogin, $this->smbPassword);

            $this->get_created_smb_credential_id = $smb->get_smb_id;
        }

        if($this->toggleSchedule === 'Yes')
        {
            $schedule = new Schedule();

            $schedule->create($this->scanDescription, $this->timezone, $this->scheduleStartDate, $this->scheduleFrequency, $this->scheduleRecurrence);

            $this->get_created_schedule_id = $schedule->get_schedule_id;
        }

        /**
         * Create Target
         */
        $target = new Target();

        $target->create(
            $this->scanDescription,
            $this->targetList,
            $this->targetPorts,
            $this->alivetest,
            $this->targetExclude,
            $this->created_port_list_id,
            $this->get_created_ssh_credential_id,
            $this->sshPort,
            $this->get_created_smb_credential_id
        );

        $this->created_target_id = $target->get_target_id;

        /**
         * Create Scan
         */
        $scan = new Scan();

        $scan->create(
            $this->scanName,
            $this->scanDescription,
            $this->scanConfigID,
            $this->created_target_id,
            $this->hostOrdering,
            $this->maxTests,
            $this->maxHosts,
            $this->scannerUUID,
            $this->get_created_schedule_id,
            $this->created_alert_id
        );

        $this->modalFormVisible = false;
        $this->currentPage = 1;
        $this->resetFields();
        $this->stopPolling = 'No';

        if($scan->get_create_result == 0) {
            $this->emit('scan-created');
            $this->emit('confetti');
        } elseif($scan->get_create_result == 1) {
            $this->emit('scan-created', [
                'title'     => 'Scan Creation',
                'icon'      => 'failure',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        }
    }

    public function taskStart($taskID)
    {
        $this->authorize('start_scans');

        $scan = new Scan();

        $scan->start($taskID);

        if($scan->get_start_result == 0) {
            // $this->emit('scan-start');
            // sleep(1);
            $this->emit('confetti');
        } elseif ($scan->get_start_result == 2) {
            $this->emit('scan-start', [
                'title'     => 'Knowledge Base is refreshing. Please wait a few minutes.',
                'icon'      => 'info',
                'timer'     => $this->alertTimer,
                'iconColor' => '#716add',
            ]);
        } elseif ($scan->get_start_result == 3) {
            $this->emit('scan-start', [
                'title'     => 'Backend is down. Please restart the services. Thanks and sorry for the inconvenience.',
                'icon'      => 'error',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        } else {
            $this->emit('scan-start', [
                'title'     => 'Error Starting Scan',
                'icon'      => 'error',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        }
    }

    public function taskStop($taskID)
    {
        $this->authorize('stop_scans');

        $scan = new Scan();

        $scan->stop($taskID);

        $this->emit('scan-stop', [
            'title'     => 'Scan Stopped',
            'icon'      => 'success',
            'timer'     => $this->alertTimer,
            'iconColor' => 'green',
        ]);
    }

    public function taskLock($taskID)
    {
        $this->authorize('lock_scans');

        $scan = new Scan();

        $scan->lock($taskID);

        if($scan->get_lock_result == 0) {
            $this->emit('scan-lock', [
                'title'     => 'Scan Locked',
                'icon'      => 'success',
                'timer'     => $this->alertTimer,
                'iconColor' => 'green',
            ]);
        } elseif($scan->get_lock_result == 1) {
            $this->emit('scan-lock', [
                'title'     => 'Scan Lock',
                'icon'      => 'failure',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        }
    }

    public function taskUnlock($taskID)
    {
        $this->authorize('unlock_scans');

        $scan = new Scan();

        $scan->unlock($taskID);

        if($scan->get_unlock_result == 0) {
            $this->emit('scan-unlock', [
                'title'     => 'Scan Unlocked',
                'icon'      => 'success',
                'timer'     => $this->alertTimer,
                'iconColor' => 'green',
            ]);
        } elseif($scan->get_unlock_result == 1) {
            $this->emit('scan-unlock', [
                'title'     => 'Scan Unlock',
                'icon'      => 'failure',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        }
    }

    public function taskClone($taskID)
    {
        $this->authorize('clone_scans');

        $scan = new Scan();

        $scan->clone($taskID);

        if($scan->get_clone_result == 0) {
            $this->emit('scan-clone', [
                'title'     => 'Scan Cloned',
                'icon'      => 'success',
                'timer'     => $this->alertTimer,
                'iconColor' => 'green',
            ]);
        } elseif($scan->get_clone_result == 1) {
            $this->emit('scan-clone', [
                'title'     => 'Scan Clone',
                'icon'      => 'failure',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        }
    }

    public function taskResume($taskID)
    {
        $this->authorize('restart_scans');

        $scan = new Scan();

        $scan->resume($taskID);

        $this->dispatchBrowserEvent('scan-resume-confetti');

         if($scan->get_resume_result == 0) {
            $this->emit('scan-resume', [
                'title'     => 'Scan Restarted',
                'icon'      => 'success',
                'timer'     => $this->alertTimer,
                'iconColor' => 'green',
            ]);
        } elseif ($scan->get_resume_result == 2) {
            $this->emit('scan-resume', [
                'title'     => 'Knowledge Base is refreshing. Please wait a few minutes.',
                'icon'      => 'info',
                'timer'     => $this->alertTimer,
                'iconColor' => '#716add',
            ]);
        } elseif ($scan->get_resume_result == 3) {
            $this->emit('scan-resume', [
                'title'     => 'Service is down. Please restart the services.',
                'icon'      => 'error',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        } elseif ($scan->get_resume_result == 1) {
            $this->emit('scan-resume', [
                'title'     => 'Error Restarting Scan',
                'icon'      => 'error',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        }
    }

    public function taskDelete($taskID)
    {
        $this->authorize('delete_scans');

        $scan = new Scan();

        $scan->delete($taskID);

        $this->deleteModalFormVisible = false;
        
        if($scan->get_delete_result == 0) {
            $this->emit('scan-deleted', [
                'title'     => 'Scan Deleted',
                'icon'      => 'success',
                'timer'     => $this->alertTimer,
                'iconColor' => 'green',
            ]);
        } else {
            $this->emit('scan-deleted', [
                'title'     => 'Error Deleting Scan',
                'icon'      => 'error',
                'timer'     => $this->alertTimer,
                'iconColor' => 'red',
            ]);
        }
        
        return $scan->get_delete_result;
    }

    public function resetFilters()
    {
        $this->reset('filters');
    }

    public function updatedFilters()
    {
        $this->resetPage();
    }

    public function exportSelected()
    {
        return response()->streamDownload(function () {
            echo (clone $this->rowsQuery)
                ->unless($this->selectAll, fn($query) => $query->whereKey($this->selected))
                ->toCsv();
        }, 'tasks.csv');
    }

    public function deleteSelected()
    {
        (clone $this->rowsQuery)
            ->unless($this->selectAll, fn($query) => $query->whereKey($this->selected))
            ->delete();

        $this->unSelectAll();
        $this->showDeleteModal = false;
    }

    public function getRowsQueryProperty()
    {
        $query = Task::query()
            ->when($this->filters['name'], fn ($query, $name) => $query->where('name', $name))
            ->when($this->filters['run_status'], fn ($query, $run_status) => $query->where('run_status', $run_status))
            ->where('name', 'like', '%'.$this->search.'%')
            ->orWhere('comment', 'like', '%'.$this->search.'%');

       return $this->applySorting($query);
    }

    public function getRowsProperty()
    {
        return $this->rowsQuery->paginate($this->pageNumbers);
    }

    public function getConfigs(): string
    {
        return $this->configs = Configs::get();
    }

    public function tasksAll(): int
    {
        return $this->scansAll = Task::distinct()
           ->count();
    }

    public function tasksNew(): int
    {
        return $this->scansNew = Task::distinct()
           ->where('run_status', '=',  2)
           ->count();
    }

    public function tasksCompleted(): int
    {
        return $this->scansCompleted = Task::distinct()
           ->where('run_status', '=',  1)
           ->count();
    }

    public function tasksRunning(): int
    {
        return $this->scansRunning = Task::distinct()
           ->where('run_status', '=',  4)
           ->count();
    }

    public function exportLastReport($task)
    {
        $uuid = Str::uuid();
        $fileName = $uuid.'.csv';

        $headers = array(
            "Content-type"        => "text/csv",
            "Content-Disposition" => "attachment; filename=$fileName",
            "Pragma"              => "no-cache",
            "Cache-Control"       => "must-revalidate, post-check=0, pre-check=0",
            "Expires"             => "0"
        );

        $columns = array(
            'KB', 
            'CVSS', 
            'Severity', 
            'Asset', 
            'Port', 
            'Vulnerability',
            'Summary',
            'Insight',
            'Impact',
            'Affected',
            'Evidence',
            'Solution',
            'Solution_Type',
            'Detection',
            'CVSSv2_Vector',
            'Category',
            'Scan',
            'CVE',
            'References'
        );

        $this->getReport = Reports::where('task', '=', $task)
            ->select('id')
            ->orderBy('id', 'DESC')
            ->limit(1)
            ->get()
            ->toArray();

        if(empty($this->getReport[0]['id'])) {
            $this->getReport[0]['id'] = null;
        }

        $query = Results::where('report', '=', $this->getReport[0]['id'])
            ->where('results.type', '!=', 'Error Message')
            ->select(
                'results.nvt as KB',
                'nvts.cvss_base as CVSS',
                DB::raw('CASE 
                WHEN results.severity >= "9.0" AND results.severity <= "10" THEN "Critical"
                WHEN results.severity >= "7.0" AND results.severity <= "8.9" THEN "High"
                WHEN results.severity >= "4.0" AND results.severity <= "6.9" THEN "Medium"
                WHEN results.severity >= "0.1" AND results.severity <= "3.9" THEN "Low"
                WHEN results.severity <= "0" THEN "Log"
                END Severity'),
                'results.host as Asset',
                'results.port as Port',
                'nvts.name as Vulnerability',
                'nvts.summary as Summary',
                'nvts.insight as Insight',
                'nvts.impact as Impact',
                'nvts.affected as Affected',
                'results.description as Evidence',
                'nvts.solution as Solution',
                'nvts.solution_type as Solution_Type',
                'nvts.vuldetect as Detection',
                'nvts.cvssv2_base_vector as CVSSv2_Vector',
                'nvts.family as Category',
                'tasks.name as Scan',
                'nvts.cve as CVE',
                'nvts.xref as References'
            )
            ->leftJoin('nvts', 'results.nvt', '=', 'nvts.oid')
            ->leftJoin('reports', 'results.report', '=', 'reports.id')
            ->leftJoin('tasks', 'results.task', '=', 'tasks.id')
            ->orderBy('nvts.cvss_base', $this->sortDirection)
            ->get();

        $callback = function() use($query, $columns) {
            $file = fopen('php://output', 'w');
            fputcsv($file, $columns);

            foreach ($query as $task) {
                $row['KB']  = $task->KB;
                $row['CVSS']    = $task->CVSS;
                $row['Severity']    = $task->Severity;
                $row['Asset']    = $task->Asset;
                $row['Port']  = $task->Port;
                $row['Vulnerability']  = $task->Vulnerability;
                $row['Summary']  = $task->Summary;
                $row['Insight']  = $task->Insight;
                $row['Impact']  = $task->Impact;
                $row['Affected']  = $task->Affected;
                $row['Evidence']  = $task->Evidence;
                $row['Solution']  = $task->Solution;
                $row['Solution_Type']  = $task->Solution_Type;
                $row['Detection']  = $task->Detection;
                $row['CVSSv2_Vector']  = $task->CVSSv2_Vector;
                $row['Category']  = $task->Category;
                $row['Scan']  = $task->Scan;
                $row['CVE']  = $task->CVE;
                $row['References']  = $task->References;

                fputcsv($file, array(
                    $row['KB'], 
                    $row['CVSS'], 
                    $row['Severity'], 
                    $row['Asset'], 
                    $row['Port'], 
                    $row['Vulnerability'],
                    $row['Summary'],
                    $row['Insight'],
                    $row['Impact'],
                    $row['Affected'],
                    $row['Evidence'],
                    $row['Solution'],
                    $row['Solution_Type'],
                    $row['Detection'],
                    $row['CVSSv2_Vector'],
                    $row['Category'],
                    $row['Scan'],
                    $row['CVE'],
                    $row['References'],
                ));
            }

            fclose($file);
        };

        return response()->stream($callback, 200, $headers);

    }

    public function render()
    {
        $this->authorize('show_scans');

        if($this->selectAll) {
            $this->selected = $this->rows->pluck('id')->map(fn($id) => (string) $id);
        }

        return view('livewire.scan.page', [
            'scans'             => $this->rows,
            'configs'           => $this->getConfigs(),
            'scansAll'          => $this->tasksAll(),
            'scansNew'          => $this->tasksNew(),
            'scansCompleted'    => $this->tasksCompleted(),
            'scansRunning'      => $this->tasksRunning(),
        ]);
    }
}