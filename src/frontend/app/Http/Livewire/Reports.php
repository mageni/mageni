<?php

namespace App\Http\Livewire;

use Livewire\Component;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

class Reports extends Component
{
    use AuthorizesRequests;

    public function vulnReport()
    {
        return redirect()->to('/reports/vulnerabilities');
    }
    
    public function render()
    {
        return view('livewire.reports');
    }
}
