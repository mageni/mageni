<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

class Task extends Model
{
    use HasFactory;

    const CREATED_AT = 'creation_time';
    const UPDATED_AT = 'modification_time';

    const STATUSES = [
        '0'     =>  'Delete Requested',
        '1'     =>  'Completed',
        '2'     =>  'New',
        '3'     =>  'Requested',
        '4'     =>  'Running',
        '10'    =>  'Stop Requested',
        '11'    =>  'Stop Waiting',
        '12'    =>  'Stoppped',
        '13'    =>  'Interrupted',
        '14'    =>  'Ultimate Delete Requested',
        '15'    =>  'Stop Requested Giveup',
        '16'    =>  'Delete Waiting',
        '17'    =>  'Ultimate Delete Waiting'
    ];

    protected $table = 'tasks';

    protected $connection = 'sqlitemanager';

    public function getDates()
    {
        return [
            'creation_time',
            'modification_time',
            'schedule_next_time',
            'start_time',
            'end_time'
        ];
    }

    protected $fillable = ['creation_time'];


    public function getStatusColorAttribute()
    {
        return [
                'success' => 'green',
                'failed' => 'red',
            ][$this->status] ?? 'cool-gray';
    }

    public function getDateForHumansAttribute()
    {
        return $this->date->format('M, d Y');
    }

    public function getDateForEditingAttribute()
    {
        return $this->date->format('m/d/Y');
    }

    public function setDateForEditingAttribute($value)
    {
        $this->date = Carbon::parse($value);
    }
}
