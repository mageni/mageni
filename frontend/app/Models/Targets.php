<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Targets extends Model
{
    use HasFactory;

    protected $table = 'targets';

    protected $connection = 'sqlitemanager';

    public function getDates()
    {
        return [
            'creation_time',
            'modification_time'
        ];
    }
}
