<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Reports extends Model
{
    use HasFactory;

    protected $table = 'reports';

    protected $connection = 'sqlitemanager';

    const SOLUTION = [
        'VendorFix' =>  'Patch',
        'Mitigation' =>  'Mitigation',
        'NoneAvailable' =>  'NoneAvailable',
        'WillNotFix' =>  'WillNotFix',
        'Workaround' =>  'Workaround',
    ];

    public function getDates()
    {
        return [
            'date',
            'start_time',
            'end_time'
        ];
    }
}
