<?php

namespace App\Http\Livewire\Reports;

use Livewire\WithFileUploads;
use Livewire\WithPagination;
use App\Models\{
    Reports,
    Results,
    Task
};

use App\Http\Livewire\Traits\{
    Methods,
    Variables,
    MultiStepForm,
    WithBulkActions,
    WithSorting
};

use Illuminate\Support\Facades\DB;

use Livewire\Component;

class Page extends Component
{
    use WithFileUploads,
        WithPagination,
        WithSorting,
        WithBulkActions,
        Methods,
        Variables,
        MultiStepForm;

    public $task;
    public $reportDetails;
    public $getReport;
    public $results;
    public $taskName;
    public $scanDetails;

    public $search = '';
    public $filter = [
        'cvss_base' => '',
        'host' => '',
        'Scan'  => '',
        'CVSS' => '',
        'Vulnerability' => '',
        'name' => '',
        'nvt' => '',
        'Asset' => '',
        'Category' => '',
        'date' => '',
        'Solution' => '',
        'solution_type' => '',
    ];

    public $severityOrder;

    public function mount($task = null)
    {
        $this->task = $task;

        $this->taskName = Task::select('name')->where('id', '=', $this->task)->first();
    }

    public function scanDetails(): mixed
    {
        return $this->scanDetails = Task::where('id', '=', $this->task)
            ->select(
                'tasks.name as Scan',
                'tasks.comment as scanDescription',
                'tasks.run_status',
                'tasks.start_time',
                'tasks.end_time',
                'tasks.creation_time'
            )
            ->first();
    }

    public function severitySort()
    {
        return $this->severityOrder = 'desc';
    }

    public function getRowsQueryProperty()
    {
        $this->getReport = Reports::where('task', '=', $this->task)
            ->select('id')
            ->orderBy('id', 'DESC')
            ->limit(1)
            ->get()
            ->toArray();

        if(empty($this->getReport[0]['id'])) {
            $this->getReport[0]['id'] = null;
        }

        $query = Results::query()
            ->where('report', '=', $this->getReport[0]['id'])
            ->where('results.type', '!=', 'Error Message')
            ->select(
                'results.id',
                'nvts.cvss_base as CVSS',
                'nvts.solution_type as Solution',
                'results.host as Asset',
                'results.port as Port',
                'nvts.name as Vulnerability',
                'nvts.family as Category',
                'tasks.name as Scan',
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

    public function getRowsCSVProperty()
    {
        $this->getReport = Reports::where('task', '=', $this->task)
            ->select('id')
            ->orderBy('id', 'DESC')
            ->limit(1)
            ->get()
            ->toArray();

        if(empty($this->getReport[0]['id'])) {
            $this->getReport[0]['id'] = null;
        }

        $query = Results::query()
            ->where('report', '=', $this->getReport[0]['id'])
            ->where('results.type', '!=', 'Error Message')
            ->select(
                'results.nvt as KB',
                'nvts.cvss_base as CVSS',
                DB::raw('CASE 
                WHEN results.severity >= "9.0" AND results.severity <= "10" THEN "Critical"
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

    public function getRowsProperty()
    {
        return $this->rowsQuery->paginate($this->pageNumbers);
    }

    public function vulnDetails($id)
    {
        return redirect()->to('/scan/vuln/'.$id);
    }

    public function resetFilters()
    {
        $this->reset('filter', 'search');
    }

    /**
     * Return in CSV the complete scan
     *
     * @return void
     */
    public function exportReport()
    {
        return response()->streamDownload(function () {
            echo (clone $this->rowsCSV)
                ->toCsv();
        }, 'results.csv');
    }

    /**
     * Return in CSV selected rows
     *
     * @return void
     */
    public function exportSelected()
    {
        return response()->streamDownload(function () {
            echo (clone $this->rowsCSV)
                ->unless($this->selectAll, fn($query) => $query->whereKey($this->selected))
                ->toCsv();
        }, 'results.csv');
    }

    public function render()
    {
        if($this->selectAll) {
            $this->selected = $this->rows->pluck('id')->map(fn($id) => (string) $id);
        }

        return view('livewire.reports.page', [
            'reportsInfo' => $this->rows,
            'scanDetails' => $this->scanDetails()
        ]);
    }
}
