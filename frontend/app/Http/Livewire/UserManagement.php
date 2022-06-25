<?php

namespace App\Http\Livewire;

use Livewire\Component;
use App\Models\User;
use App\Models\Version;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use App\Http\Livewire\Traits\WithSorting;
use App\Http\Livewire\Traits\WithBulkActions;
use Livewire\WithPagination;
use Illuminate\Support\Facades\Hash;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

class UserManagement extends Component
{
    use WithSorting,
        AuthorizesRequests,
        WithBulkActions,
        WithPagination;

    public $usersPermissions;
    public $permissions;
    public $roles;
    public $role;
    public $name;
    public $password;
    public $email;
    public $modalFormVisible = false;
    public $modalDeleteUser = false;
    public $modalEditUser = false;
    public $user;
    public $userID;
    public $userName;
    public $userEmail;
    public $userPermissions;
    public $userPassword;
    public $toggleChangeRole = 'No';
    public $togglePasswordReset = 'No';
    public $userRoles;
    public $userRolesCollect;

    public $endpoint;
    public $version; 
    public $license; 
    public $plan;

    public $pageNumbers = 25;

    public $filters = [
        'name' => '',
        'email' => '',
    ];

    public $search = '';

    protected $rules = [
        'name' => 'required|min:6',
        'email' => 'required|email',
        'password' => 'required|min:6',
    ];

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

    public function upgrade()
    {
        return redirect()->to('https://buy.stripe.com/7sI7sQ0gs5MK8dq288');
    }

    public function getRoles()
    {
        return $this->roles = Role::whereNotIn('name', ['root'])->get();
    }
    
    public function getPermissions()
    {
        return $this->permissions = Permission::all()->pluck('name');
    }

    public function getUsers()
    {
        return $this->users = User::get();
    }
   
    public function getUsersPermissions()
    {
        return $this->usersPermissions = User::with('permissions')->paginate();
    }

    public function createUser()
    {
        $this->authorize('create_users');

        $this->validate([
            'name' => 'required|min:2',
            'email' => 'required|email',
            'password' => 'required|min:6|max:32',
            'role' => 'required'
        ]);
        
        $user = new User();
        $user->name = $this->name;
        $user->email = $this->email;
        $user->password = Hash::make($this->password);
        $user->assignRole($this->role);
        $user->save();

        $this->closeUserModal();

        session()->flash('message', 'User created successfully');
 
        return redirect()->to('/users');
    }

    public function getRowsQueryProperty()
    {
        /**
         * Do not declare the property
         */
        $query = User::query()
            ->when($this->filters['name'], fn ($query, $name) => $query->where('name', $name))
            ->when($this->filters['email'], fn ($query, $email) => $query->where('email', $email))
            ->search('name', $this->search);

       return $this->applySorting($query);
    }

    public function getRowsProperty()
    {
        return $this->rowsQuery->paginate($this->pageNumbers);
    }

    public function newUserModal()
    {
        $this->authorize('create_users');

        $this->modalFormVisible = true;
    }
  
    public function closeUserModal()
    {
        $this->modalFormVisible = false;
    }

    public function deleteUserModal()
    {
        $this->authorize('delete_users');

        $this->modalFormVisible = true;
    }

    public function editModalOpen($id)
    {
        $this->authorize('edit_users');

        $this->user = User::find($id);

        $this->reset('userEmail', 'userName', 'toggleChangeRole', 'togglePasswordReset', 'userPassword');

        $this->userID = $this->user->id;

        $this->userName = $this->user->name;

        $this->userEmail = $this->user->email;
        
        $this->userPermissions = $this->user->getAllPermissions();
        
        $this->userRoles = $this->user->getRoleNames();

        $this->modalEditUser = true;
    }

    public function deleteModalOpen($id)
    {
        $this->authorize('delete_users');

        $this->user = User::find($id);

        $this->userID = $this->user->id;

        $this->modalDeleteUser = true;
    }

    public function deleteUser($id)
    {
        $this->authorize('delete_users');

        User::find($id)->delete();

        $this->modalDeleteUser = false;

        session()->flash('message', 'User deleted successfully');
 
        return redirect()->to('/users');
    }

    public function saveEditUser($id)
    {
        $this->authorize('edit_users');

        if($this->togglePasswordReset === 'Yes')
        {
            $this->validate([
                'userName' => 'required|min:2',
                'userEmail' => 'required|email',
                'userPassword' => 'required|email'
            ]);
        }elseif($this->toggleChangeRole === 'Yes') {
            $this->validate([
                'userName' => 'required|min:2',
                'userEmail' => 'required|email',
                'userRoles' => 'required'
            ]);
        }elseif($this->toggleChangeRole === 'Yes' && 
                $this->togglePasswordReset === 'Yes') {
            $this->validate([
                'userName' => 'required|min:2',
                'userEmail' => 'required|email',
                'userPassword' => 'required|email'
            ]);
        }

        $user = User::find($id);

        $user->name = $this->userName;
        $user->email = $this->userEmail;
        if(!is_null($this->userPassword))
        {
            $user->password = Hash::make($this->userPassword);
        }
        $user->syncRoles($this->userRoles);
        $user->save();

        $this->deleteModalClose();

        session()->flash('message', 'User modified successfully');
 
        return redirect()->to('/users');
    }

    public function editModalClose()
    {
        $this->reset('userEmail', 'userName', 'toggleChangeRole', 'togglePasswordReset', 'userPassword');
        
        $this->modalEditUser = false;
    }

    public function deleteModalClose()
    {
        $this->reset('userEmail', 'userName', 'toggleChangeRole', 'togglePasswordReset', 'userPassword');
        
        $this->modalDeleteUser = false;
    }
  
    public function closeDeleteUserModal()
    {
        $this->modalDeleteUser = false;
    }

    public function render()
    {
        $this->authorize('show_users');

        return view('livewire.user-management', [
            'users' => $this->rows,
            'roles' => $this->getRoles(),
        ]);
    }
}