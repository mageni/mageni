<?php

namespace App\Http\Livewire\Scan\Cards;

use App\Models\Task;
use Livewire\Component;

class Tasks extends Component
{
    public function render()
    {
        return view('livewire.scan.cards.tasks', [
            'scans' => Task::count()
        ]);
    }
}
