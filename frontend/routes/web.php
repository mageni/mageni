<?php

use Illuminate\Support\Facades\Route;
use App\Http\Livewire\Reports\Page as ReportsPage;
use App\Http\Livewire\Scan\Page as ScanPage;
use App\Http\Livewire\Vulnerabilities\Page as VulnPage;
use App\Http\Livewire\Kb\Page as KbPage;
use App\Http\Livewire\KbDetails\Page as KbDetails;
use App\Http\Livewire\UserManagement as Users;
use App\Http\Livewire\Notification\Email;
use App\Http\Livewire\Reports;
use App\Http\Livewire\Analytics\Vulnerabilities;
use App\Http\Livewire\Dashboard\Page as Dashboard;
use App\Http\Livewire\Analytics\VulnerabilitiesDetail;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;

// Route::get('/', Dashboard::class)->name('scans');

Route::get('/notifications/email/{scan}/{email}', Email::class)->name('email');

Route::group(['middleware' => [
    'auth:sanctum',
    'verified',
]], function () {
    Route::get('/', Dashboard::class)->name('dashboard');

    Route::get('/dashboard', Dashboard::class)->name('dashboard');

    Route::get('/scan', ScanPage::class)->name('scans');

    Route::get('/scan/{task}', ReportsPage::class)->name('reports');

    Route::get('/scan/vuln/{vuln}', VulnPage::class)->name('vulnerability');

    Route::get('/knowledgebase', KbPage::class)->name('kb');

    Route::get('/knowledgebase/{uuid}', KbDetails::class)->name('kbdetails');

    Route::get('/users', Users::class)->name('users');
    
    Route::get('/reports', Reports::class)->name('reports');

    Route::get('/reports/vulnerabilities', Vulnerabilities::class)->name('vulnerabilities');

    Route::get('/reports/vulnerabilities/{nvt}', VulnerabilitiesDetail::class)->name('vulndetails');

    Route::get('/risks', function () {
        return view('dashboard');
    })->name('risks');

    Route::get('/assets', function () {
        return view('dashboard');
    })->name('assets');

    Route::get('/plugins', function () {
        return view('dashboard');
    })->name('plugins');
});

