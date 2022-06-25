<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AlertMethodData extends Model
{
    use HasFactory;

    protected $table = 'alert_method_data';

    protected $connection = 'sqlitemanager';
}
