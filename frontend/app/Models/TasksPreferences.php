<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TasksPreferences extends Model
{
    use HasFactory;

    protected $table = 'task_preferences';

    protected $connection = 'sqlitemanager';
}
