<?php

namespace App\Http\Livewire\Traits;

trait Methods
{
    public $showEditModal = false;
    public $modalFormVisible = false;
    public string $stopPolling = 'No';
    public $update; 

    public function resetFields()
    {
        $this->currentPage = 1;

        $this->reset(
            'scanName',
            'scanDescription',
            'getAlertUUID',
            'emailTo',
            'emailCC',
            'emailNotification',
            'targetAlive',
            'scanConfigID',
            'created_target_id',
            'maxTests',
            'hostOrdering',
            'currentPage',
            'get_created_schedule_id',
            'scanSpeed',
            'portRange',
            'credentialType',
            'targetList',
            'sshLogin',
            'sshPassword',
            'sshPhrase',
            'targetPorts',
            'sshKey',
            'smbLogin',
            'smbPassword',
            'esxiLogin',
            'esxiPassword',
            'hasSMBCredentials',
            'hasSSHCredentials',
            'credentialSSHID',
            'snmpCommunity',
            'targetExclude',
            'snmpUsername',
            'sshPort',
            'snmpPassword',
            'snmpAuthAlgorithm',
            'snmpPrivacyAlgorithm',
            'snmpPrivacyPassword',
            'credentialSMBID',
            'timezone',
            'hasNotification',
            'getScheduleUUID',
            'hasSchedule',
            'scheduleStartDate',
            'scheduleFrequency',
            'toggleSchedule',
            'toggleNotification',
            'email',
            'toggleExcludeTargets',
            'toggleSSHCredentials',
            'toggleSMBCredentials',
            'toggleESXiCredentials',
            'toggleSNMPCredentials',
            'toggleSNMPCredentials'
        );
    }

    public function resetCredentials()
    {
        $this->reset(
            'get_created_smb_credential_id',
            'get_created_ssh_credential_id',
            'created_port_list_id',
            'created_target_id',
            'get_created_schedule_id'
        );
    }
}
