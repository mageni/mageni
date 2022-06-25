<?php

namespace App\Http\Livewire\Kb;

use App\Http\Livewire\Traits\Methods;
use App\Http\Livewire\Traits\MultiStepForm;
use App\Http\Livewire\Traits\Variables;
use App\Http\Livewire\Traits\WithBulkActions;
use App\Http\Livewire\Traits\WithSorting;
use App\Models\Reports;
use App\Models\Results;
use Illuminate\Support\Facades\DB;
use Livewire\Component;

use App\Models\KnowledgeBase;
use Livewire\WithFileUploads;
use Livewire\WithPagination;

class Page extends Component
{
    use WithFileUploads,
        WithPagination,
        WithSorting,
        WithBulkActions,
        Methods,
        Variables,
        MultiStepForm;

    public $results;
    public $creationTime;

    public $columnFilter = [
        'status' => '',
        'owner' => '',
        'name'  => '',
        'run_status' => '',
    ];

    public function getRowsQueryProperty()
    {
        $this->creationTime = KnowledgeBase::query()
            ->select('creation_time')
            ->orderBy('nvts.creation_time', 'DESC')
            ->first();

        $query = KnowledgeBase::query()
            ->select(
                'nvts.family',
                'nvts.uuid',
                'nvts.name',
                'nvts.cve',
                'nvts.xref',
                'nvts.category',
                'nvts.cvss_base',
                'nvts.creation_time',
                'nvts.modification_time',
                'nvts.modification_time',
                'nvts.cvssv2_base_score',
                'nvts.cvssv2_base_vector',
                'nvts.cvssv2_base_score_overall',
                'nvts.cvssv2_base_impact',
                'nvts.cvssv2_base_exploit',
                'nvts.cvssv2_em_access_complex',
                'nvts.cvssv2_em_access_vector',
                'nvts.cvssv2_em_authentication',
                'nvts.cvssv2_impact_ai',
                'nvts.cvssv2_impact_ii',
                'nvts.cvssv2_impact_ci',
                'nvts.cvssv3_base_score',
                'nvts.cvssv3_base_score_overall',
                'nvts.cvssv3_base_exploit',
                'nvts.cvssv3_base_impact',
                'nvts.cvssv3_base_vector',
                'nvts.cvssv3_em_attack_complex',
                'nvts.cvssv3_em_attack_vector',
                'nvts.cvssv3_em_priv_required',
                'nvts.cvssv3_em_user_interact',
                'nvts.cvssv3_scope',
                'nvts.cvssv3_impact_ai',
                'nvts.cvssv3_impact_ci',
                'nvts.cvssv3_impact_ii',
                'nvts.cwe_id',
                'nvts.cpe',
                'nvts.pci_dss',
                'nvts.url_ref',
                'nvts.cve_date',
                'nvts.patch_date',
            )
            ->when($this->columnFilter['name'], fn ($query, $name) => $query->where('name', $name))
//            ->when($this->filter['solution_type'], fn ($query, $solution_type) => $query->where('solution_type', $solution_type))
//            ->when($this->filter['Category'], fn ($query, $Category) => $query->where('Category', $Category))
//            ->when($this->filter['CVSS'], fn ($query, $CVSS) => $query->where('nvts.cvss_base', $CVSS))
            ->orderBy('nvts.cvss_base', $this->sortDirection)
            ->orderBy('nvts.creation_time', 'DESC')
            ->search('nvts.name', $this->search);

        return $this->applySorting($query);
    }

    public function kbDetails($uuid)
    {
        return redirect()->to('/knowledgebase/'.$uuid);
    }

    public function getRowsProperty()
    {
        return $this->rowsQuery->paginate($this->pageNumbers);
    }

    public function render()
    {
        return view('livewire.kb.page', [
            'kb' => $this->rows
        ]);
    }
}
