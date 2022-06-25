<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class TargetsLoginData extends Model
{
    use HasFactory;

    protected $table = 'targets_login_data';

    protected $connection = 'sqlitemanager';
}
