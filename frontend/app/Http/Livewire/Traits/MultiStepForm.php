<?php

namespace App\Http\Livewire\Traits;

use App\Rules\ValidateSSHKey;

trait MultiStepForm
{
    use Variables;

    public function firstStepSubmit(): int
    {
        if($this->showEditModal)
        {
            $this->validate([
                'scanName' => 'required|string|min:4|max:30',
                'scanDescription' => 'required|string|min:4|max:120',
            ]);
        } else {
            $this->validate([
                'scanName' => 'required|string|min:4|max:30',
                'scanDescription' => 'required|string|min:4|max:120',
                'scanConfigID' => 'required|uuid',
            ]);
        }

        return $this->currentPage = 2;
    }

    public function secondStepSubmit(): int
    {
        if($this->toggleExcludeTargets === 'Yes')
        {
            $this->validate([
                'targetList'    => 'required|string|min:4|max:1024',
                'scanSpeed'     => 'required|digits_between:1,2',
                'targetExclude' => 'required|string|different:targetList',
                'targetAlive'   => 'required|digits_between:1,2',
            ]);
        }elseif($this->targetPorts === 'customports') {
            $this->validate([
                'targetList'    => 'required|string|min:4|max:1024',
                'scanSpeed'     => 'required|digits_between:1,2',
                'portRange'     => 'required',
                'targetAlive'   => 'required|digits_between:1,2',
            ]);
        }else {
            $this->validate([
                'targetList'    => 'required|string|min:4|max:1024',
                'scanSpeed'     => 'required|digits_between:1,2',
                'targetAlive'   => 'required|digits_between:1,2',
            ]);
        }

        if($this->targetAlive === '2') {
            $this->alivetest = 'ICMP Ping';
        } elseif ($this->targetAlive === '4') {
            $this->alivetest = 'ARP Ping';
        } elseif ($this->targetAlive === '7') {
            $this->alivetest = 'ICMP, TCP-ACK Service &amp; ARP Ping';
        } elseif ($this->targetAlive === '3') {
            $this->alivetest = 'ICMP &amp; TCP-ACK Service Ping';
        } elseif ($this->targetAlive === '8') {
            $this->alivetest = 'Consider Alive';
        } elseif ($this->targetAlive === '1') {
            $this->alivetest = 'TCP-ACK Service Ping';
        } elseif ($this->targetAlive === '16') {
            $this->alivetest = 'TCP-SYN Service Ping';
        } elseif ($this->targetAlive === '6') {
            $this->alivetest = 'ICMP &amp; ARP Ping';
        } elseif ($this->targetAlive === '5') {
            $this->alivetest = 'TCP-ACK Service &amp; ARP Ping';
        }

        if ($this->scanSpeed === '1') {
            $this->hostOrdering = 'random';
            $this->maxTests = '2';
            $this->maxHosts = '10';
        } elseif ($this->scanSpeed === '2') {
            $this->hostOrdering = 'random';
            $this->maxTests = '5';
            $this->maxHosts = '20';
        } elseif ($this->scanSpeed === '3') {
            $this->hostOrdering = 'random';
            $this->maxTests = '10';
            $this->maxHosts = '30';
        }

        return $this->currentPage = 3;
    }

    public function thirdStepSubmit(): int
    {
        if($this->toggleSSHCredentials === 'Yes' ||
            $this->toggleSSHCredentials === 'Create' || 
            $this->toggleSSHCredentials === 'Modify' || 
            $this->toggleSSHCredentials === 'Edit')
        {
            if($this->credentialType === 'up')
            {
                $this->validate([
                    'sshLogin'      => 'required|string|min:4|max:128',
                    'sshPassword'   => 'required|string|min:4|max:128',
                    'sshPort' => 'required|integer|min:1|max:65535',
                ]);
            } 
            
            if($this->credentialType === 'usk') 
            {
                $this->validate([
                    'sshLogin'      => 'required|string|min:4|max:128',
                    'sshPhrase'     => 'required|string|min:4|max:128',
                    'sshKey'        => ['required', new ValidateSSHKey()],
                    'sshPort' => 'required|integer|min:1|max:65535',
                ]);
            }
        } 
        
        if($this->toggleSMBCredentials === 'Yes' || 
            $this->toggleSMBCredentials === 'Create' || 
            $this->toggleSMBCredentials === 'Modify' || 
            $this->toggleSMBCredentials === 'Edit') 
        {
            $this->validate([
                'smbLogin' => 'required|string|min:4|max:128',
                'smbPassword' => 'required|string|min:4|max:128',
            ]);
        } 

        return $this->currentPage = 4;
    }

    public function fourthStepSubmit(): int
    {
        if($this->toggleSchedule === 'Create' || $this->toggleSchedule === 'Modify' || $this->toggleSchedule === 'Yes')
        {
            $this->validate([
                'scheduleFrequency' => 'required|string|max:32',
                'scheduleStartDate' => 'required|date_format:m/d/Y H:i',
            ]);
        }

        return $this->currentPage = 5;
    }

    public function fifthStepSubmit(): int
    {
        if($this->toggleNotification === 'Create' || $this->toggleNotification === 'Edit')
        {
            $this->validate([
                'email' => 'required|email|max:64'
            ]);
        }

        return $this->currentPage = 6;
    }

    public function backPage(): string
    {
        return $this->currentPage--;
    }
}
