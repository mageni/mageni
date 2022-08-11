<?php

namespace App\Http\Livewire\Vulnerabilities;

use App\Models\Results;
use Livewire\Component;

class Page extends Component
{
    public $vuln;
    public $details;

    public function mount($vuln = null)
    {
        $this->vuln = $vuln;
    }

    public function details()
    {
        return $this->details = Results::where('results.id', '=', $this->vuln)
            ->select(
                'results.host',
                'results.hostname',
                'nvts.name',
                'nvts.cvss_base',
                'nvts.cve',
                'nvts.xref',
                'nvts.family',
                'nvts.solution_type',
                'nvts.solution_type',
                'nvts.cvssv2_base_vector',
                'nvts.cvssv2_base_score',
                'nvts.cvssv2_base_score_overall',
                'nvts.cvssv2_base_impact',
                'nvts.cvssv2_base_exploit',
                'nvts.cvssv2_em_access_vector',
                'nvts.cvssv2_em_access_complex',
                'nvts.cvssv2_em_authentication',
                'nvts.cvssv2_impact_ci',
                'nvts.cvssv2_impact_ci',
                'nvts.cvssv2_impact_ii',
                'nvts.cvssv2_impact_ai',
                'nvts.cvssv3_base_vector',
                'nvts.cvssv3_base_score',
                'nvts.cvssv3_base_score_overall',
                'nvts.cvssv3_base_impact',
                'nvts.cvssv3_base_impact',
                'nvts.cvssv3_base_exploit',
                'nvts.cvssv3_em_attack_vector',
                'nvts.cvssv3_em_attack_complex',
                'nvts.cvssv3_em_priv_required',
                'nvts.cvssv3_em_user_interact',
                'nvts.cvssv3_scope',
                'nvts.cvssv3_impact_ci',
                'nvts.cwe_id',
                'nvts.cpe',
                'nvts.pci_dss',
                'nvts.url_ref',
                'nvts.cve_date',
                'nvts.patch_date',
                'nvts.summary',
                'nvts.insight',
                'nvts.vuldetect',
                'nvts.affected',
                'nvts.solution',
                'nvts.intezer',
                'nvts.virustotal',
                'results.date',
                'results.port',
                'results.nvt',
                'results.nvt',
                'results.type',
                'results.description',
                'results.severity',
                'results.severity',
                'results.qod_type'
            )
            ->leftJoin('nvts', 'results.nvt', '=', 'nvts.oid')
            ->first();
    }

    public function render()
    {
        return view('livewire.vulnerabilities.page', [
            'details' => $this->details(),
        ]);
    }
}
