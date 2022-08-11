<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Configs extends Model
{
    use HasFactory;

    const CREATED_AT = 'creation_time';
    const UPDATED_AT = 'modification_time';

    protected $table = 'configs';

    protected $connection = 'sqlitemanager';

    public function getDates()
    {
        return [
            'creation_time',
            'modification_time'
        ];
    }
}
