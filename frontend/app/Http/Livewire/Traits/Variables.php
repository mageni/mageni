<?php

namespace App\Http\Livewire\Traits;

trait Variables
{
    public $scannerUUID = '08b69003-5fc2-4037-a479-93b440211c73';
    public $scanConfigID = '';
    public $sshPort = '22';
    public $snmpVersion = 'snmpv1orv2';
    public $credentialType = 'up';
    public $alertTimer = '1500';
    public $errorTimer = '3000';
    public $credentialSSHID;
    public $getCredentialSMBID;
    public $getCredentialESXIID;
    public $getCredentialSNMPID;
    public $credentialSMBID;
    public $credentialESXIID;
    public $credentialSNMPID;
    public $credentialTypeUserPass = 'up';
    public $credentialTypeUserSSHKey = 'usk';
    public $sshType;
    public $credentialTypeUserSNMP = 'snmp';
    public $credentialTypePassOnly = 'pw';

    public $deleteModalFormVisible = false;
    public $deleteModalConfirmationFormVisible = false;
    public $editModalFormVisible = false;
    public $taskID;
    public $deleteTaskID;
    public $taskName;
    public $deleteQuery;
    public $schedules;

    //Email
    public $emailTo;
    public $emailCC;
    public $emailSubject;
    public $emailContent;

    //License
    public $endpoint;
    public $version; 
    public $license; 
    public $plan;

    // Schedules
    public $scheduleID;
    public $scheduleName;
    public $scheduleDescription;
    public $scheduleStartDate;
    public $scheduleEndDate;
    public $scheduleFrequency;
    public $scheduleRecurrence;
    public $timezone = 'UTC';
    public $icalendar;

    // Create Scan Modal
    public $configs;
    public $scansAll;
    public $scansNew;
    public $scansCompleted;
    public $scansRunning;
    public $exportLastReport;
    public $exportLastReportQuery;
    public $configName;
    public $configUUID;
    public $scanName;
    public $email;
    public $scanUUID;
    public $scanID;
    public $scanDescription;
    public $targetID;
    public $schedID;
    public $targets;
    public $credentials;

    //Edit Scan Modal
    public $getTask;
    public $getSchedule;
    public $getScheduleInfo;
    public $getScheduleiCal;
    public $getScheduleUUID;
    public $getScheduleFT;
    public $getScheduleTZ;
    public $getTarget;
    public $getTargetInfo;
    public $getAlert;
    public $getAlertNotEmpty;
    public $getAlertID;
    public $getAlertUUID;
    public $getAlertData;
    public $getToEmail;
    public $getAlertURL;
    public $getTaskPrefInfo;
    public $getTaskPrefMaxHosts;
    public $getPortsInfo;
    public $getPortsUUID;
    public $getTargetLogin;
    public $loginType;
    public $loginCredIDSSH;
    public $loginCredSSHUser;
    public $loginCredSSHPass;
    public $loginCredSMBUser;
    public $loginCredESXIUser;
    public $loginCredSNMPV3User;
    public $v3AUA;
    public $v3PRA;
    public $loginCredSNMPV1User;
    public $getConfig;

    // Create Target Modal
    public $targetModalFormVisible = false;

    public $targetName;
    public $targetDescription;

    public $credentialSSH;
    public $credentialWindows;
    public $credentialESXi;
    public $credentialSNMP;
    public $snmpAuthAlg;
    public $snmpPrivacyAlg;

    //Ports Modal
    public $portRange;
    public $customports;

    //SSH Modal
    public bool $sshModalForm = false;

    //SMB Modal
    public bool $smbModalForm = false;

    //SNMP Modal
    public bool $snmpModalForm = false;

    //ESXi Modal
    public bool $esxiModalForm = false;

    //Schedule Modal
    public bool $scheduleModalForm = false;

    //Credentials Models
    public $credentialName;
    public $credentialDescription;
    public $credentialLogin;
    public $credentialPassword;

    //SSH Credentials
    public $sshLogin;
    public $sshPassword;
    public $sshPasswordEdit = 'password';
    public $smbPasswordEdit = 'password';
    public $esxiPasswordEdit = 'password';
    public $snmpPasswordEdit = 'password';
    public $sshPhrase;
    public $sshKey;

    //SMB Credentials
    public $smbLogin;
    public $smbPassword;

    //ESXi Credentials
    public $esxiLogin;
    public $esxiPassword;

    //SNMP Credentials
    public $snmpCommunity;
    public $snmpUsername;
    public $snmpPassword;
    public $snmpPrivacyPassword;
    public $snmpAuthAlgorithm;
    public $snmpAuthAlgorithmSHA2;
    public $snmpPrivacyAlgorithm;
    public $credentialPrivate;
    public $credentialPublic;
    public $credentialAuAlgorithm;
    public $credentialCommunity;
    public $credentialPriAlg;
    public $credentialPriPass;
    public $sshKeyUpload;
    public $readSSHKey;

    /**
     * Create Variables
     */
    public $created_port_list_id;
    public $created_alert_id;
    public $modified_alert_id;
    public $created_target_id;
    public $created_scan_id;
    public $kbrealoading;

    /**
     * Create SSH Credentials Variables
     */
    public $get_created_ssh_credential_id;

    /**
     * Create SMB Credentials Variables
     */
    public $get_created_smb_credential_id;

    /**
     * Create ESXi Credentials Variables
     */
    public $get_created_esxi_credential_id;

    /**
     * Create Schedule Credentials Variables
     */
    public $get_created_schedule_id;

    /**
     * Create SNMP Credentials Variables
     */
    public $create_snmp_credential;
    public $get_created_snmp_credential_id;

    public $showFilters;
    public $showDeleteModal = false;
    public $filters = [
        'status' => '',
        'owner' => '',
        'name'  => '',
        'run_status' => '',
    ];

    public $search = '';
    public $perPage = 10;

    public $editing;

    public $pageNumbers = 25;

    public $currentPage = 1;

    protected $rules = [
        'editing.name' => 'required',
        'editing.owner' => 'required',
        'editing.comment' => 'required'
    ];

    // Second Step Create Scan Form
    public $alivetest;
    public $ports;
    public $targetList;
    public $targetUUID;
    public $targetExclude;
    public $targetExcludeClean = '';
    public $targetPorts = 'ab33f6b0-57f8-11e1-96f5-406186ea4fc5';
    public $targetAlive = '3';
    public $scanSpeed = '2';
    public $emailNotification;
    public $hostOrdering;
    public $maxTests;
    public $maxHosts;

    // Slow Speed
    private $slowHostOrdering = 'sequential';

    public bool $togleButton;

    public $togglePortScan = 'No';
    public $toggleHostDiscovery = 'No';
    public $togglePerformance = 'No';
    public $toggleSSHCredentials = 'No';
    public $hasSSHCredentials = 'No';
    public $optionSSHCredentials = '';
    public $optionSMBCredentials = '';
    public $toggleSMBCredentials = 'No';
    public $hasSMBCredentials = 'No';
    public $toggleESXiCredentials = 'No';
    public $toggleSNMPCredentials = 'No';
    public $toggleSchedule;
    public $toggleNotification;
    public $unsetValue = 0;
    public $hasSchedule = 'No';
    public $hasNotification = 'No';
    public $toggleExcludeTargets = 'No';
    public $customizePorts = 'No';

    public $pages = [
        1 => [
            'heading' => 'Scan Details',
            'subheading' => 'Give the scan a name and description and select a scan template',
        ],
        2 => [
            'heading' => 'Targets',
            'subheading' => 'Configure your scan targets',
        ],
        3 => [
            'heading' => 'Credentials',
            'subheading' => 'Setup the credentials for authenticated scans',
        ],
        4 => [
            'heading' => 'Schedules',
            'subheading' => 'Configure the schedules',
        ],
        5 => [
            'heading' => 'Notifications',
            'subheading' => 'Send email notifications',
        ],
        6 => [
            'heading' => 'Review',
            'subheading' => 'Review and save the scan',
        ],
    ];

}
