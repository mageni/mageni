<?php

namespace App\Http\Livewire\Dashboard;

use Livewire\Component;
use App\Models\Results;
use App\Models\Task;
use App\Models\Hosts;
use Illuminate\Support\Facades\DB;
use App\Models\Version;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;

class Page extends Component
{
    public $allvuln;
    public $informational;
    public $criticalvuln;
    public $avgcvss;
    public $highvuln;
    public $mediumvuln;
    public $lowvuln;
    public $scansAll;
    public $scansNew;
    public $scansCompleted;
    public $scansRunning;
    public $scansStopped;
    public $vulnJan;
    public $vulnFeb;
    public $vulnMar;
    public $vulnApr;
    public $vulnMay;
    public $vulnJun;
    public $vulnJul;
    public $vulnAug;
    public $vulnSep;
    public $vulnOct;
    public $vulnNov;
    public $vulnDec;
    public $allAssets;
    public $top10Critical;

    public $endpoint;
    public $version; 
    public $license; 
    public $plan;

    public function mount()
    {
        $this->endpoint = "https://www.mageni.net/api/v1/token/plan";

        $this->version = Version::select('api_key')->find(1);
        $this->license = $this->version->api_key;
       
        $response = Http::withToken($this->version->api_key)->get($this->endpoint);

        if(Str::contains($response, 'paid')) {
            $this->plan = 'Paid';
            Log::info("You are on the paid plan.");
        } else {
            $this->plan = 'Free';
            Log::info("You are on the free plan.");
        }
    }
    
    public function allVuln(): int
    {
        return $this->allvuln = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->count();
    }
    
    public function top10Critical()
    {
        return $this->top10Critical = Results::distinct()
            ->select('results.id', 'nvts.name', 'nvts.oid')
            ->leftJoin('nvts', 'results.nvt', '=', 'nvts.oid')
            ->where('severity', '=', 10)
            ->take(10)
            ->get();
    }

    public function top10Details($id)
    {
        return redirect()->to('/reports/vulnerabilities/'.$id);
    }

    public function allAssets(): int
    {
        return $this->allAssets = Hosts::distinct()
            ->select('hosts.id')
            ->count();
    }

    public function average()
    {
        return $this->avgcvss = Results::distinct()
            ->select(
                DB::raw('avg(results.severity) as avgseverity'),
            )
            ->where('severity', '>=', 0.1)
            ->get();
    }

    public function vulnJan()
    {
        $year = date("Y");
        $date1 = $year.'-02-01';
        $date2 = $year.'-01-01';

        return $this->vulnJan = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnFeb()
    {
        $year = date("Y");
        $date1 = $year.'-03-01';
        $date2 = $year.'-02-01';

        return $this->vulnFeb = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnMar()
    {
        $year = date("Y");
        $date1 = $year.'-04-01';
        $date2 = $year.'-03-01';

        return $this->vulnMar = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnApr()
    {
        $year = date("Y");
        $date1 = $year.'-05-01';
        $date2 = $year.'-04-01';

        return $this->vulnApr = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnMay()
    {
        $year = date("Y");
        $date1 = $year.'-06-01';
        $date2 = $year.'-05-01';

        return $this->vulnMay = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnJun()
    {
        $year = date("Y");
        $date1 = $year.'-07-01';
        $date2 = $year.'-06-01';

        return $this->vulnJun = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnJul()
    {
        $year = date("Y");
        $date1 = $year.'-08-01';
        $date2 = $year.'-07-01';

        return $this->vulnJul = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnAug()
    {
        $year = date("Y");
        $date1 = $year.'-09-01';
        $date2 = $year.'-08-01';

        return $this->vulnAug = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnSep()
    {
        $year = date("Y");
        $date1 = $year.'-10-01';
        $date2 = $year.'-09-01';

        return $this->vulnSep = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnOct()
    {
        $year = date("Y");
        $date1 = $year.'-11-01';
        $date2 = $year.'-10-01';

        return $this->vulnOct = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnNov()
    {
        $year = date("Y");
        $date1 = $year.'-12-01';
        $date2 = $year.'-11-01';

        return $this->vulnNov = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }

    public function vulnDec()
    {
        $year = date("Y");
        $date1 = $year.'-12-31';
        $date2 = $year.'-12-01';

        return $this->vulnDec = Results::distinct()
            ->select('results.id')
            ->where('severity', '>=', 0.1)
            ->whereRaw("datetime(results.date,'unixepoch') <= strftime(?)", [$date1])
            ->whereRaw("datetime(results.date,'unixepoch') >= strftime(?)", [$date2])
            ->count();
    }
    
    public function info(): int
    {
        return $this->informational = Results::distinct()
            ->select('results.id')
            ->where('severity', '=', 0.0    )
            ->count();
    }

    public function criticalVuln(): int
    {
        return $this->criticalvuln = Results::distinct()
            ->select('results.id')
            ->where('results.severity', '>=', 9.0)
            ->count();
    }

    public function highVuln(): int
    {
        return $this->highvuln = Results::distinct()
            ->select('results.id')
            ->where('results.severity', '<=', 8.9)
            ->where('results.severity', '>=', 7.0)
            ->count();
    }

    public function mediumVuln(): int
    {
        return $this->mediumvuln = Results::distinct()
            ->select('results.id')
            ->where('results.severity', '<=', 6.9)
            ->where('results.severity', '>=', 4.0)
            ->count();
    }

    public function lowVuln(): int
    {
        return $this->lowvuln = Results::distinct()
            ->select('results.id')
            ->where('results.severity', '<=', 3.9)
            ->where('results.severity', '>=', 0.1)
            ->count();
    }

    public function tasksAll(): int
    {
        return $this->scansAll = Task::distinct()
           ->count();
    }

    public function tasksNew(): int
    {
        return $this->scansNew = Task::distinct()
           ->where('run_status', '=',  2)
           ->count();
    }

    public function tasksCompleted(): int
    {
        return $this->scansCompleted = Task::distinct()
           ->where('run_status', '=',  1)
           ->count();
    }

    public function tasksRunning(): int
    {
        return $this->scansRunning = Task::distinct()
           ->where('run_status', '=',  4)
           ->count();
    }
    
    public function tasksStopped(): int
    {
        return $this->scansStopped = Task::distinct()
           ->where('run_status', '=',  12)
           ->count();
    }

    public function render(Request $request)
    {
        // dd($request);

        return view('livewire.dashboard.page', [
            'allvuln'           => $this->allVuln(),
            'avgcvss'           => $this->average(),
            'informational'     => $this->info(),
            'criticalvuln'      => $this->criticalVuln(),
            'highvuln'          => $this->highVuln(),
            'mediumvuln'        => $this->mediumVuln(),
            'lowvuln'           => $this->lowVuln(),
            'scansAll'          => $this->tasksAll(),
            'scansNew'          => $this->tasksNew(),
            'scansCompleted'    => $this->tasksCompleted(),
            'scansRunning'      => $this->tasksRunning(),
            'scansStopped'      => $this->tasksStopped(),
            'vulnJan'           => $this->vulnJan(),
            'vulnFeb'           => $this->vulnFeb(),
            'vulnMar'           => $this->vulnMar(),
            'vulnApr'           => $this->vulnApr(),
            'vulnMay'           => $this->vulnMay(),
            'vulnJun'           => $this->vulnJun(),
            'vulnJul'           => $this->vulnJul(),
            'vulnAug'           => $this->vulnAug(),
            'vulnSep'           => $this->vulnSep(),
            'vulnOct'           => $this->vulnOct(),
            'vulnNov'           => $this->vulnNov(),
            'vulnDec'           => $this->vulnDec(),
            'allAssets'         => $this->allAssets(),
            'top10Critical'     => $this->top10Critical(),
        ]);
    }
}
