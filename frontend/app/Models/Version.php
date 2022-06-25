<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Version extends Model
{
    use HasFactory;

    protected $table = 'version';

    protected $connection = 'sqlite';

    public $timestamps = false;

    protected $fillable = [
        'api_key'
    ];
}
