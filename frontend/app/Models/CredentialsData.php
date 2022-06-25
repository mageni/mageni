<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class CredentialsData extends Model
{
    use HasFactory;

    protected $table = 'credentials_data';

    protected $connection = 'sqlitemanager';
}
