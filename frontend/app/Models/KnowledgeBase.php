<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class KnowledgeBase extends Model
{
    use HasFactory;

    protected $table = 'nvts';

    protected $connection = 'sqlitemanager';

    public function getDates()
    {
        return [
            'creation_time',
            'modification_time'
        ];
    }
}
