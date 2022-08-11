<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class Version extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        DB::table('version')->insert([
            'api_key' => 'ieaJXpA3EC37aZug27g0WQ8Ktz0jE7K8lOBkilGE',
            'feed' => '202206090614',
            'frontend' => '202206090614',
            'backend' => '202206090614',
        ]);
    }
}
