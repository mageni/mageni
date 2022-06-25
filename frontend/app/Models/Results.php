<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Results extends Model
{
    use HasFactory;

    protected $table = 'results';

    const CREATED_AT = 'date';

    protected $connection = 'sqlitemanager';

    public function getDates()
    {
        return [
            'date'
        ];
    }
}
