<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use App\Models\User;

class PermissionsSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        /**
         * Search for first user 
         */
        $userOne = User::where('id', 1)->first();

        /**
         * Create roles
         */
        $root = Role::create(['name' => 'root']);
        $ceo = Role::create(['name' => 'CEO']);
        $cfo = Role::create(['name' => 'CFO']);
        $ciso = Role::create(['name' => 'CISO']);
        $manager = Role::create(['name' => 'Manager']);
        $analyst = Role::create(['name' => 'Analyst']);
        $investigator = Role::create(['name' => 'Investigator']);
        $auditor = Role::create(['name' => 'Auditor']);
        $sysadmin = Role::create(['name' => 'SysAdmin']);
        $viewer = Role::create(['name' => 'Viewer']);

        /**
         * Reports permissions
         */
        $show_reports = Permission::create(['name' => 'show_reports']);
        $edit_reports = Permission::create(['name' => 'edit_reports']);
        $delete_reports = Permission::create(['name' => 'delete_reports']);
        $download_reports = Permission::create(['name' => 'download_reports']);
        $compare_reports = Permission::create(['name' => 'compare_reports']);
        $search_reports = Permission::create(['name' => 'search_reports']);

        /**
         * Analytics permissions
         */
        $show_analytics = Permission::create(['name' => 'show_analytics']);
        $download_analytics = Permission::create(['name' => 'download_analytics']);

        /**
         * Scans permissions
         */
        $create_scans = Permission::create(['name' => 'create_scans']);
        $start_scans = Permission::create(['name' => 'start_scans']);
        $restart_scans = Permission::create(['name' => 'restart_scans']);
        $stop_scans = Permission::create(['name' => 'stop_scans']);
        $show_scans = Permission::create(['name' => 'show_scans']);
        $edit_scans = Permission::create(['name' => 'edit_scans']);
        $delete_scans = Permission::create(['name' => 'delete_scans']);
        $clone_scans = Permission::create(['name' => 'clone_scans']);
        $lock_scans = Permission::create(['name' => 'lock_scans']);
        $unlock_scans = Permission::create(['name' => 'unlock_scans']);
        $download_scans = Permission::create(['name' => 'download_scans']);
        $search_scans = Permission::create(['name' => 'search_scans']);

        /**
         * Users permissions
         */
        $create_users = Permission::create(['name' => 'create_users']);
        $show_users = Permission::create(['name' => 'show_users']);
        $edit_users = Permission::create(['name' => 'edit_users']);
        $delete_users = Permission::create(['name' => 'delete_users']);
        $lock_users = Permission::create(['name' => 'lock_users']);
        $unlock_users = Permission::create(['name' => 'unlock_users']);
        $download_users = Permission::create(['name' => 'download_users']);
        $search_users = Permission::create(['name' => 'search_users']);
        
        /**
         * Policies permissions
         */
        $create_policies = Permission::create(['name' => 'create_policies']);
        $show_policies = Permission::create(['name' => 'show_policies']);
        $edit_policies = Permission::create(['name' => 'edit_policies']);
        $delete_policies = Permission::create(['name' => 'delete_policies']);
        $download_policies = Permission::create(['name' => 'download_policies']);
        $search_policies = Permission::create(['name' => 'search_policies']);

        /**
         * KB permissions
         */
        $show_kb = Permission::create(['name' => 'show_kb']);
        $download_kb = Permission::create(['name' => 'download_kb']);
        $search_kb = Permission::create(['name' => 'search_kb']);

        /**
         * Results permissions
         */
        $show_results = Permission::create(['name' => 'show_results']);
        $validate_results = Permission::create(['name' => 'validate_results']);
        $download_results = Permission::create(['name' => 'download_results']);
        $search_results = Permission::create(['name' => 'search_results']);

        /**
         * Vulnerabilities permissions
         */
        $show_vulnerabilities = Permission::create(['name' => 'show_vulnerabilities']);
        $validate_vulnerabilities = Permission::create(['name' => 'validate_vulnerabilities']);
        $download_vulnerabilities = Permission::create(['name' => 'download_vulnerabilities']);
        $search_vulnerabilities = Permission::create(['name' => 'search_vulnerabilities']);

        /**
         * Override permissions
         */
        $create_override = Permission::create(['name' => 'create_override']);
        $edit_override = Permission::create(['name' => 'edit_override']);
        $download_override = Permission::create(['name' => 'download_override']);
        $delete_override = Permission::create(['name' => 'delete_override']);
        $search_override = Permission::create(['name' => 'search_override']);
        $show_override = Permission::create(['name' => 'show_override']);

        /**
         * Notes permissions
         */
        $create_notes = Permission::create(['name' => 'create_notes']);
        $edit_notes = Permission::create(['name' => 'edit_notes']);
        $download_notes = Permission::create(['name' => 'download_notes']);
        $delete_notes = Permission::create(['name' => 'delete_notes']);
        $search_notes = Permission::create(['name' => 'search_notes']);
        $show_notes = Permission::create(['name' => 'show_notes']);

        /**
         * Ticket permissions
         */
        $show_tickets = Permission::create(['name' => 'show_tickets']);
        $create_tickets = Permission::create(['name' => 'create_tickets']);
        $edit_tickets = Permission::create(['name' => 'edit_tickets']);
        $delete_tickets = Permission::create(['name' => 'delete_tickets']);
        $download_tickets = Permission::create(['name' => 'download_tickets']);
        $search_tickets = Permission::create(['name' => 'search_tickets']);
        
        /**
         * Dashboard permissions 
         */
        $show_dashboard = Permission::create(['name' => 'show_dashboard']);

        /**
         * Assets permissions 
         */
        $show_assets = Permission::create(['name' => 'show_assets']);
        $edit_assets = Permission::create(['name' => 'edit_assets']);
        $download_assets = Permission::create(['name' => 'download_assets']);
        $search_assets = Permission::create(['name' => 'search_assets']);

        /**
         * Audit permissions 
         */
        $show_audit = Permission::create(['name' => 'show_audit']);
        $download_audit = Permission::create(['name' => 'download_audit']);
        $search_audit = Permission::create(['name' => 'search_audit']);

        /**
         * Assign permissions to manager
         */
        $show_reports->assignRole($manager);
        $edit_reports->assignRole($manager);
        $delete_reports->assignRole($manager);
        $download_reports->assignRole($manager);
        $compare_reports->assignRole($manager);
        $search_reports->assignRole($manager);

        $show_analytics->assignRole($manager);
        $download_analytics->assignRole($manager);

        $show_scans->assignRole($manager); 
        $start_scans->assignRole($manager); 
        $restart_scans->assignRole($manager); 
        $stop_scans->assignRole($manager); 
        $create_scans->assignRole($manager); 
        $edit_scans->assignRole($manager); 
        $delete_scans->assignRole($manager); 
        $clone_scans->assignRole($manager); 
        $lock_scans->assignRole($manager); 
        $unlock_scans->assignRole($manager); 
        $download_scans->assignRole($manager); 
        $search_scans->assignRole($manager);

        $show_users->assignRole($manager); 
        $create_users->assignRole($manager); 
        $edit_users->assignRole($manager); 
        $delete_users->assignRole($manager); 
        $lock_users->assignRole($manager); 
        $unlock_users->assignRole($manager); 
        $download_users->assignRole($manager); 
        $search_users->assignRole($manager);

        $create_policies->assignRole($manager);
        $show_policies->assignRole($manager);
        $edit_policies->assignRole($manager);
        $delete_policies->assignRole($manager);
        $download_policies->assignRole($manager);
        $search_policies->assignRole($manager);

        $show_kb->assignRole($manager);
        $download_kb->assignRole($manager);
        $search_kb->assignRole($manager);

        $show_results->assignRole($manager);
        $validate_results->assignRole($manager);
        $download_results->assignRole($manager);
        $search_results->assignRole($manager);

        $show_vulnerabilities->assignRole($manager);
        $validate_vulnerabilities->assignRole($manager);
        $download_vulnerabilities->assignRole($manager);
        $search_vulnerabilities->assignRole($manager);

        $show_override->assignRole($manager);
        $create_override->assignRole($manager);
        $edit_override->assignRole($manager);
        $download_override->assignRole($manager);
        $delete_override->assignRole($manager);
        $search_override->assignRole($manager);

        $show_notes->assignRole($manager);
        $create_notes->assignRole($manager);
        $edit_notes->assignRole($manager);
        $download_notes->assignRole($manager);
        $delete_notes->assignRole($manager);
        $search_notes->assignRole($manager);

        $show_tickets->assignRole($manager);
        $create_tickets->assignRole($manager);
        $edit_tickets->assignRole($manager);
        $delete_tickets->assignRole($manager);
        $download_tickets->assignRole($manager);
        $search_tickets->assignRole($manager);

        $show_dashboard->assignRole($manager);

        $show_assets->assignRole($manager);
        $edit_assets->assignRole($manager);
        $download_assets->assignRole($manager);
        $search_assets->assignRole($manager);

        $show_audit->assignRole($manager);
        $download_audit->assignRole($manager);
        $search_audit->assignRole($manager);

        /**
         * Assign permissions to viewer
         */
        $show_reports->assignRole($viewer);
        $show_analytics->assignRole($viewer);
        $show_users->assignRole($viewer);
        $show_assets->assignRole($viewer);
        $show_audit->assignRole($viewer);
        $show_dashboard->assignRole($viewer);
        $show_kb->assignRole($viewer);
        $show_policies->assignRole($viewer);
        $show_results->assignRole($viewer);
        $show_scans->assignRole($viewer);
        $show_tickets->assignRole($viewer);
        $show_vulnerabilities->assignRole($viewer);
        
        /**
         * Assign permissions to ceo
         */
        $show_dashboard->assignRole($ceo);
        $show_analytics->assignRole($ceo);

        /**
         * Assign permissions to cfo
         */
        $show_dashboard->assignRole($cfo);
        $show_analytics->assignRole($cfo);

        /**
         * Assign permissions to ciso
         */
        $show_dashboard->assignRole($ciso);
        $show_analytics->assignRole($ciso);

        /**
         * Assign permissions to analyst
         */
        $show_reports->assignRole($analyst);
        $edit_reports->assignRole($analyst);
        $download_reports->assignRole($analyst);
        $compare_reports->assignRole($analyst);
        $search_reports->assignRole($analyst);

        $show_analytics->assignRole($analyst);
        $download_analytics->assignRole($analyst);

        $show_scans->assignRole($analyst); 
        $start_scans->assignRole($analyst); 
        $stop_scans->assignRole($analyst); 
        $restart_scans->assignRole($analyst); 
        $create_scans->assignRole($analyst); 
        $edit_scans->assignRole($analyst); 
        $clone_scans->assignRole($analyst); 
        $lock_scans->assignRole($analyst); 
        $download_scans->assignRole($analyst); 
        $search_scans->assignRole($analyst);

        $create_policies->assignRole($analyst);
        $show_policies->assignRole($analyst);
        $edit_policies->assignRole($analyst);
        $download_policies->assignRole($analyst);
        $search_policies->assignRole($analyst);

        $show_kb->assignRole($analyst);
        $download_kb->assignRole($analyst);
        $search_kb->assignRole($analyst);

        $show_results->assignRole($analyst);
        $validate_results->assignRole($analyst);
        $download_results->assignRole($analyst);
        $search_results->assignRole($analyst);

        $show_vulnerabilities->assignRole($analyst);
        $validate_vulnerabilities->assignRole($analyst);
        $download_vulnerabilities->assignRole($analyst);
        $search_vulnerabilities->assignRole($analyst);

        $show_override->assignRole($analyst);
        $create_override->assignRole($analyst);
        $edit_override->assignRole($analyst);
        $download_override->assignRole($analyst);
        $search_override->assignRole($analyst);

        $show_notes->assignRole($analyst);
        $create_notes->assignRole($analyst);
        $edit_notes->assignRole($analyst);
        $download_notes->assignRole($analyst);
        $search_notes->assignRole($analyst);

        $show_tickets->assignRole($analyst);
        $create_tickets->assignRole($analyst);
        $edit_tickets->assignRole($analyst);
        $download_tickets->assignRole($analyst);
        $search_tickets->assignRole($analyst);

        $show_dashboard->assignRole($analyst);

        $show_assets->assignRole($analyst);
        $edit_assets->assignRole($analyst);
        $search_assets->assignRole($analyst);

        $show_audit->assignRole($analyst);
        $search_audit->assignRole($analyst);

        /**
         * Assign permissions to investigator
         */
        $show_reports->assignRole($investigator);
        $download_reports->assignRole($investigator);
        $compare_reports->assignRole($investigator);
        $search_reports->assignRole($investigator);

        $show_analytics->assignRole($investigator);
        $download_analytics->assignRole($investigator);

        $show_scans->assignRole($investigator); 
        $download_scans->assignRole($investigator); 
        $search_scans->assignRole($investigator);

        $show_policies->assignRole($investigator);
        $download_policies->assignRole($investigator);
        $search_policies->assignRole($investigator);

        $show_kb->assignRole($investigator);
        $download_kb->assignRole($investigator);
        $search_kb->assignRole($investigator);

        $show_results->assignRole($investigator);
        $download_results->assignRole($investigator);
        $search_results->assignRole($investigator);

        $show_vulnerabilities->assignRole($investigator);
        $download_vulnerabilities->assignRole($investigator);
        $search_vulnerabilities->assignRole($investigator);

        $show_override->assignRole($investigator);
        $download_override->assignRole($investigator);
        $search_override->assignRole($investigator);

        $show_notes->assignRole($investigator);
        $download_notes->assignRole($investigator);
        $search_notes->assignRole($investigator);

        $show_tickets->assignRole($investigator);
        $download_tickets->assignRole($investigator);
        $search_tickets->assignRole($investigator);

        $show_dashboard->assignRole($investigator);

        $show_assets->assignRole($investigator);
        $download_assets->assignRole($investigator);
        $search_assets->assignRole($investigator);

        $show_audit->assignRole($investigator);
        $download_audit->assignRole($investigator);
        $search_audit->assignRole($investigator);

        /**
         * Assign permissions to auditor
         */
        $show_reports->assignRole($auditor);
        $download_reports->assignRole($auditor);
        $compare_reports->assignRole($auditor);
        $search_reports->assignRole($auditor);

        $show_users->assignRole($auditor); 
        $download_users->assignRole($auditor); 
        $search_users->assignRole($auditor);

        $show_analytics->assignRole($auditor);
        $download_analytics->assignRole($auditor);

        $show_scans->assignRole($auditor); 
        $download_scans->assignRole($auditor); 
        $search_scans->assignRole($auditor);

        $show_policies->assignRole($auditor);
        $download_policies->assignRole($auditor);
        $search_policies->assignRole($auditor);

        $show_kb->assignRole($auditor);
        $download_kb->assignRole($auditor);
        $search_kb->assignRole($auditor);

        $show_results->assignRole($auditor);
        $download_results->assignRole($auditor);
        $search_results->assignRole($auditor);

        $show_vulnerabilities->assignRole($auditor);
        $download_vulnerabilities->assignRole($auditor);
        $search_vulnerabilities->assignRole($auditor);

        $show_override->assignRole($auditor);
        $download_override->assignRole($auditor);
        $search_override->assignRole($auditor);

        $show_notes->assignRole($auditor);
        $create_notes->assignRole($auditor);
        $download_notes->assignRole($auditor);
        $search_notes->assignRole($auditor);

        $show_tickets->assignRole($auditor);
        $download_tickets->assignRole($auditor);
        $search_tickets->assignRole($auditor);

        $show_dashboard->assignRole($auditor);

        $show_assets->assignRole($auditor);
        $download_assets->assignRole($auditor);
        $search_assets->assignRole($auditor);

        $show_audit->assignRole($auditor);
        $download_audit->assignRole($auditor);
        $search_audit->assignRole($auditor);

        /**
         * Assign permissions to sysadmin
         */
        $show_reports->assignRole($sysadmin);
        $download_reports->assignRole($sysadmin);
        $compare_reports->assignRole($sysadmin);
        $search_reports->assignRole($sysadmin);

        $show_analytics->assignRole($sysadmin);
        $download_analytics->assignRole($sysadmin);

        $show_scans->assignRole($sysadmin); 
        $download_scans->assignRole($sysadmin); 
        $search_scans->assignRole($sysadmin);

        $show_policies->assignRole($sysadmin);
        $search_policies->assignRole($sysadmin);

        $show_kb->assignRole($sysadmin);
        $download_kb->assignRole($sysadmin);
        $search_kb->assignRole($sysadmin);

        $show_results->assignRole($sysadmin);
        $download_results->assignRole($sysadmin);
        $search_results->assignRole($sysadmin);

        $show_vulnerabilities->assignRole($sysadmin);
        $download_vulnerabilities->assignRole($sysadmin);
        $search_vulnerabilities->assignRole($sysadmin);

        $show_override->assignRole($sysadmin);
        $create_override->assignRole($sysadmin);
        $edit_override->assignRole($sysadmin);
        $download_override->assignRole($sysadmin);
        $search_override->assignRole($sysadmin);

        $show_notes->assignRole($sysadmin);
        $create_notes->assignRole($sysadmin);
        $edit_notes->assignRole($sysadmin);
        $download_notes->assignRole($sysadmin);
        $search_notes->assignRole($sysadmin);

        $show_tickets->assignRole($sysadmin);
        $create_tickets->assignRole($sysadmin);
        $edit_tickets->assignRole($sysadmin);
        $download_tickets->assignRole($sysadmin);
        $search_tickets->assignRole($sysadmin);

        $show_dashboard->assignRole($sysadmin);

        $show_assets->assignRole($sysadmin);
        $download_assets->assignRole($sysadmin);
        $search_assets->assignRole($sysadmin);

        /**
         * Assign role Administrator to first user
         */
        $userOne->assignRole($root);
    }
}
