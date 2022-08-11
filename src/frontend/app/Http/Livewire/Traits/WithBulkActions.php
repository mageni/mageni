<?php

namespace App\Http\Livewire\Traits;

trait WithBulkActions
{
    public $selected = [];
    public $selectAll = false;
    public $selectPage = false;

    public function updatedSelected()
    {
        $this->selectAll = false;
        $this->selectPage = false;
    }

    public function updatedSelectPage($value)
    {
        $this->selected = $value
            ? $this->rows->pluck('id')->map(fn($id) => (string) $id)
            : [];
    }

    public function selectAll()
    {
        $this->selectAll = true;
        $this->selected = $this->selectAll;
    }

    public function unSelectAll()
    {
        $this->selected = [];
        $this->selectAll = false;
        $this->selectPage = false;
    }

    public function getSelectedRowsQuery()
    {
        return (clone $this->rowsQuery)->unless($this->selectAll, fn($query) => $query->whereKey($this->selected));
    }
}
