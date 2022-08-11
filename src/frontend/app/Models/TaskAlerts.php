<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TaskAlerts extends Model
{
    use HasFactory;

    protected $table = 'task_alerts';

    protected $connection = 'sqlitemanager';
}
