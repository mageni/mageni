<?php

namespace App\Http\Livewire\Analytics;

use Livewire\Component;
use App\Models\Results;
use Illuminate\Support\Facades\DB;

use Livewire\WithPagination;
use App\Http\Livewire\Traits\{
    Methods,
    Variables,
    MultiStepForm,
    WithBulkActions,
    WithSorting
};

class Vulnerabilities extends Component
{
    use WithPagination,
    WithSorting,
    WithBulkActions,
    Methods,
    Variables,
    MultiStepForm;

    public $queryString = ['sortDirection'];

    public $filter = [
        'cvss_base' => '',
        'host' => '',
        'Scan'  => '',
        'CVSS' => '',
        'name' => '',
        'nvt' => '',
        'Vulnerability' => '',
        'Asset' => '',
        'Category' => '',
        'date' => '',
        'Solution' => '',
        'solution_type' => '',
    ];

    public $allvuln;
    public $criticalvuln;
    public $highvuln;
    public $mediumvuln;
    public $lowvuln;
    
    public function updatingSearch()
    {
        $this->resetPage();
    }

    public function mount()
    {
        $this->resetPage();
    }

    public function getRowsQueryProperty()
    {
        $query = Results::query()
        ->where('results.type', '!=', 'Error Message')
        ->distinct()
        ->select(
            'results.id',
            'nvts.name',
            'results.date',
            'results.nvt',
            DB::raw('COUNT(DISTINCT results.host) as hostcount'),
            'nvts.cvss_base as cvss',
            'nvts.family as category',
            'tasks.name as scan',
            'tasks.uuid'
        )
        ->leftJoin('nvts', 'results.nvt', '=', 'nvts.oid')
        ->leftJoin('reports', 'results.report', '=', 'reports.id')
        ->leftJoin('tasks', 'results.task', '=', 'tasks.id')
        ->when($this->filter['Vulnerability'], fn ($query, $Vulnerability) => $query->where('Vulnerability', $Vulnerability))
        ->when($this->filter['solution_type'], fn ($query, $solution_type) => $query->where('solution_type', $solution_type))
        ->when($this->filter['Category'], fn ($query, $Category) => $query->where('Category', $Category))
        ->when($this->filter['CVSS'], fn ($query, $CVSS) => $query->where('nvts.cvss_base', $CVSS))
        ->orderBy('nvts.cvss_base', $this->sortDirection)
        ->groupBy('nvts.name')
        ->search('nvts.name', $this->search);

        return $this->applySorting($query);
    }
    
    public function getRowsCSVProperty()
    {
        $query = Results::query()
            ->where('results.type', '!=', 'Error Message')
            ->select(
                'results.nvt as KB',
                'nvts.cvss_base as CVSS',
                DB::raw('CASE 
                WHEN results.severity >= "9.0" THEN "Critical"
                WHEN results.severity >= "7.0" AND results.severity <= "8.9" THEN "High"
                WHEN results.severity >= "4.0" AND results.severity <= "6.9" THEN "Medium"
                WHEN results.severity >= "0.1" AND results.severity <= "3.9" THEN "Low"
                WHEN results.severity <= "0" THEN "Log"
                END Severity'),
                'results.host as Asset',
                'results.port as Port',
                'nvts.name as Vulnerability',
                'nvts.summary as Summary',
                'nvts.insight as Insight',
                'nvts.impact as Impact',
                'nvts.affected as Affected',
                'results.description as Evidence',
                'nvts.solution as Solution',
                'nvts.solution_type as Solution_Type',
                'nvts.vuldetect as Detection',
                'nvts.cvssv2_base_vector as CVSSv2_Vector',
                'nvts.family as Category',
                'tasks.name as Scan',
                DB::raw("datetime(reports.date,'unixepoch') as Date"),
                'nvts.cve as CVE',
                'nvts.xref as References'
            )
            ->leftJoin('nvts', 'results.nvt', '=', 'nvts.oid')
            ->leftJoin('reports', 'results.report', '=', 'reports.id')
            ->leftJoin('tasks', 'results.task', '=', 'tasks.id')
            ->when($this->filter['Vulnerability'], fn ($query, $Vulnerability) => $query->where('Vulnerability', $Vulnerability))
            ->when($this->filter['solution_type'], fn ($query, $solution_type) => $query->where('solution_type', $solution_type))
            ->when($this->filter['Category'], fn ($query, $Category) => $query->where('Category', $Category))
            ->when($this->filter['CVSS'], fn ($query, $CVSS) => $query->where('nvts.cvss_base', $CVSS))
            ->orderBy('nvts.cvss_base', $this->sortDirection)
            ->search('nvts.name', $this->search);

        return $this->applySorting($query);
    }

    public function exportReport()
    {
        return response()->streamDownload(function () {
            echo (clone $this->rowsCSV)
                ->toCsv();
        }, 'results.csv');
    }

    public function exportSelected()
    {
        return response()->streamDownload(function () {
            echo (clone $this->rowsCSV)
                ->unless($this->selectAll, fn($query) => $query->whereKey($this->selected))
                ->toCsv();
        }, 'results.csv');
    }

    public function getRowsProperty()
    {
        return $this->rowsQuery->paginate($this->pageNumbers);
    }

    public function vulnDetails($id)
    {
        return redirect()->to('/reports/vulnerabilities/'.$id);
    }

    // public function allVuln(): int
    // {
    //     return $this->allvuln = Results::distinct()
    //         ->select('results.id')
    //         ->where('severity', '>=', 0.1)
    //         ->count();
    // }

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

    public function render()
    {
        if($this->selectAll) {
            $this->selected = $this->rows->pluck('id')->map(fn($id) => (string) $id);
        }

        return view('livewire.analytics.vulnerabilities', [
            'details'       => $this->rows,
            'criticalvuln'  => $this->criticalVuln(),
            'highvuln'      => $this->highVuln(),
            'mediumvuln'    => $this->mediumVuln(),
            'lowvuln'       => $this->lowVuln(),
        ]);
    }
}
