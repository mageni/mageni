<div>
    <x-headers.users />
    <main class="py-10">
        <!-- This example requires Tailwind CSS v2.0+ -->
  
        <div class="max-w-full mx-auto sm:px-6 lg:px-6">

            @if($plan === 'Free')
            <div class="bg-yellow-50 border-l-4 mb-5 border-yellow-400 p-4">
                <div class="flex">
                <div class="flex-shrink-0">
                    <!-- Heroicon name: solid/exclamation -->
                    <svg class="h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-yellow-700">
                        You are in the Community plan.
                        <a 
                            href="https://buy.stripe.com/7sI7sQ0gs5MK8dq288" 
                            target="_blank"
                            class="font-medium underline text-yellow-700 hover:text-yellow-600"
                        > 
                            Subscribe to unlock more features like notifications, schedules, migrations, manage users, and support
                        </a>
                    </p>
                </div>
                </div>
            </div>
            @endif
              
            <div class="overflow-hidden sm:rounded-lg">
                <div class="py-4 space-y-4">
                    <div class="mr-1 sm:flex sm:items-center sm:justify-between">
                        
                        <div class="relative flex w-2/4 ml-1">
                            <svg width="20" height="20" fill="currentColor" class="absolute text-gray-400 transform -translate-y-1/2 left-2 top-1/2">
                                <path fill-rule="evenodd" clip-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" />
                            </svg>
                            <x-input.text
                                id="name"
                                wire:model="search"
                                type="text"
                                class="block w-full py-2 pl-8 mt-1 text-sm text-black placeholder-gray-500 border border-gray-200 rounded-md focus:border-light-blue-500 focus:ring-1 focus:ring-light-blue-500 focus:outline-none"
                                autofocus
                                placeholder="Search"
                            />
                        </div>

                            @if($plan === 'Paid')
                                <x-jet-button
                                    wire:click="newUserModal" 
                                    class="hover:shadow">
                                    New User
                                </x-jet-button>
                            @else
                                <x-jet-button
                                    x-data
                                    x-tooltip="Subscribe to create users"
                                    class="hover:shadow cursor-not-allowed">
                                    New User
                                </x-jet-button>
                            @endif

                    </div>
                </div>
            </div>
            
            <x-table class="table-auto">
                <x-slot name="head">
                    <x-table.heading class="w-6 pr-0">
                        <x-input.checkbox wire:model="selectPage" class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"/>
                    </x-table.heading>
                    <x-table.heading sortable wire:click="sortBy('name')" :direction="$sortField === 'name' ? $sortDirection : null">Name</x-table.heading>
                    <x-table.heading sortable wire:click="sortBy('email')" :direction="$sortField === 'email' ? $sortDirection : null">Email</x-table.heading>
                    <x-table.heading sortable>Role</x-table.heading>
                    <x-table.heading sortable>Created</x-table.heading>
                    <x-table.heading sortable>Modified</x-table.heading>
                    <x-table.heading sortable></x-table.heading>
                </x-slot>
                <x-slot name="body">
                    <div>
                    {{-- {{ dd($users) }} --}}
                        @if($users->count() > 0)
                            @foreach($users as $user)
                            
                                <x-table.row wire:loading.delay.class="opacity-50" wire:target="search">
                                    <x-table.cell class="pr-0">
                                        <div>
                                            <span wire:key="{{ $loop->index }}">
                                                <input wire:key="{{ $loop->index }}" wire:model="selected" value="{{ $user->id }}" id="tasks" aria-describedby="tasks-id" name="tasks" type="checkbox" class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500">
                                            </span>
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div>
                                            <span wire:key="{{ $loop->index }}">
                                                {{ $user->name }}
                                            </span>
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div>
                                            <span wire:key="{{ $loop->index }}">
                                                {{ $user->email }}
                                            </span>
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div>
                                            <span wire:key="{{ $loop->index }}">
                                                @foreach($user->getRoleNames() as $role)
                                                    {{ $role }}
                                                @endforeach
                                            </span>
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div>
                                            @foreach($user->getRoleNames() as $role)
                                                <div>
                                                    @if($role === 'root')
                                                        <span wire:key="{{ $loop->index }}">
                                                            {{ 'On Install' }}
                                                        </span>
                                                    @else
                                                        <span wire:key="{{ $loop->index }}">
                                                            {{ $user->created_at }}
                                                        </span>
                                                    @endif
                                                </div>
                                            @endforeach
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div>
                                        @foreach($user->getRoleNames() as $role)
                                            <div>
                                                @if($role === 'root')
                                                    <span wire:key="{{ $loop->index }}">
                                                        {{ 'NA' }}
                                                    </span>
                                                @else
                                                    <span wire:key="{{ $loop->index }}">
                                                        {{ $user->updated_at }}
                                                    </span>
                                                @endif
                                            </div>
                                        @endforeach
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                       <div>
                                        @foreach($user->getRoleNames() as $role)
                                            <div>
                                                @if($role === 'root')
                                                <div class="flex flex-row space-x-2 justify-end">
                                                    <span 
                                                        wire:key="{{ $loop->index }}" 
                                                        class="font-normal text-indigo-600 hover:text-indigo-800 cursor-not-allowed"
                                                    >
                                                        {{ 'Edit' }}
                                                    </span>
                                                    <span 
                                                        wire:key="{{ $loop->index }}" 
                                                        class="font-normal text-indigo-600 hover:text-indigo-800 cursor-not-allowed"
                                                    >
                                                        {{ 'Delete' }}
                                                    </span>
                                                </div>
                                                @else
                                                    <div class="flex flex-row space-x-2 justify-end">
                                                        <span 
                                                            wire:click="editModalOpen('{{$user->id}}')" 
                                                            wire:key="{{ $loop->index }}" 
                                                            class="font-normal text-indigo-600 hover:text-indigo-800 cursor-pointer"
                                                        >
                                                            {{ 'Edit' }}
                                                        </span>
                                                        <span 
                                                            wire:click="deleteModalOpen('{{$user->id}}')" 
                                                            wire:key="{{ $loop->index }}" 
                                                            class="font-normal text-indigo-600 hover:text-indigo-800 cursor-pointer"
                                                        >
                                                            {{ 'Delete' }}
                                                        </span>
                                                    </div>
                                                @endif
                                            </div>
                                        @endforeach
                                       </div>
                                    </x-table.cell>
                                </x-table.row>
                            @endforeach
                        @else
                    </div>
                        <x-table.row>
                            <x-table.cell class="px-6 py-4 whitespace-nowrap" colspan="100%">
                                <span class="flex items-center justify-center space-x-2 text-lg font-medium text-gray-400">
                                    <i class="mr-2 fas fa-binoculars"></i>
                                    No users found.
                                </span>
                            </x-table.cell>
                        </x-table.row>
                    @endif
                </x-slot>
            </x-table>
            <div class="mt-2">
                {{ $users->links() }}
            </div>
            
        </div>
    </main>
    
    {{-- Create User Modal --}}
    <x-jet-dialog-modal wire:model.defer="modalFormVisible" maxWidth="mds">
        <x-slot name="title">
            <div class="flex justify-between">
                Create User
                <div 
                    x-data
                    x-tooltip="Close"
                    wire:click="closeUserModal" 
                    wire:key="closeUserModal-0"
                >
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-gray-500 cursor-pointer hover:text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                </div>
            </div>
        </x-slot>

        <x-slot name="content">
            <div class="px-4 py-5 mt-2 border-t border-gray-200 sm:p-0">
                <dl class="sm:divide-y sm:divide-gray-200">
                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Name
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <input 
                                wire:key="userName-12" 
                                type="text" 
                                wire:model.lazy="name" 
                                name="name" 
                                id="name" 
                                class="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm @if($errors->has('scanName')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md" placeholder="@if($errors->has('scanName')){{'Required'}}@else{{''}}@endif" 
                                aria-describedby="user-name"
                            >                                      
                            @if($errors->first('name'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('name') }}</p>
                            @else 
                                <p class="mt-1 text-sm text-gray-500">Required</p>
                            @endif
                        </dd>
                    </div>
                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Email
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <input 
                                wire:key="userEmail-12" 
                                type="text" 
                                wire:model.lazy="email" 
                                name="email" 
                                id="email" 
                                class="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm @if($errors->has('scanName')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md" placeholder="@if($errors->has('scanName')){{'Required'}}@else{{''}}@endif" 
                                aria-describedby="user-email"
                            >                                      
                            @if($errors->first('email'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('email') }}</p>
                            @else 
                                <p class="mt-1 text-sm text-gray-500">Required</p>
                            @endif
                        </dd>
                    </div>
                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Password
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <input 
                                wire:key="smbPassword-0" 
                                type="password" 
                                wire:model.lazy="password" 
                                name="password" 
                                id="password" 
                                placeholder="" 
                                class="block @if($errors->has('password')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                aria-describedby="user-password"
                            >                                   
                            @if($errors->first('password'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('password') }}</p>
                            @else 
                                <p class="mt-1 text-sm text-gray-500">Required</p>
                            @endif
                        </dd>
                    </div>

                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Role
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <select 
                                wire:key="roles-0" 
                                wire:model="role" 
                                id="roles" 
                                name="roles" 
                                class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                            >
                                   <option value="" hidden selected>Select Role...</option>
                                   <option value="CEO">CEO</option>
                                   <option value="CFO">CFO</option>
                                   <option value="CISO">CISO</option>
                                   <option value="Manager">Manager</option>
                                   <option value="Analyst">Analyst</option>
                                   <option value="Investigator">Investigator</option>
                                   <option value="Auditor">Auditor</option>
                                   <option value="SysAdmin">SysAdmin</option>
                                   <option value="Viewer">Viewer</option>
                            </select>                                  
                            @if($errors->first('role'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('role') }}</p>
                            @else
                                <p class="mt-1 text-sm text-gray-500">Required</p>
                            @endif
                        </dd>
                    </div>
                </dl>
            </div>
        </x-slot>

        <x-slot name="footer">
            <div class="flex justify-between">
                <x-jet-secondary-button wire:click="closeUserModal" >
                    {{ __('Close') }}
                </x-jet-secondary-button>
    
                <x-jet-button wire:click="createUser" >
                    {{ __('Create') }}
                </x-jet-button>
            </div>
        </x-slot>
    </x-jet-dialog-modal>

    {{-- Edit User Modal --}}
    <x-jet-dialog-modal wire:model.defer="modalEditUser" maxWidth="mds">
        <x-slot name="title">
            <div class="flex justify-between">
                Edit User
                <div 
                    x-data
                    x-tooltip="Close"
                    wire:click="editModalClose" 
                    wire:key="closeUserModal-0"
                >
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-gray-500 cursor-pointer hover:text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                </div>
            </div>
        </x-slot>

        <x-slot name="content">
            <div class="px-4 py-5 mt-2 border-t border-gray-200 sm:p-0">
                <dl class="sm:divide-y sm:divide-gray-200">
                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Name
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <input 
                                wire:key="userName-Edit-0" 
                                type="text" 
                                wire:model.lazy="userName" 
                                name="name" 
                                id="name" 
                                placeholder="{{ $userName }}"
                                class="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm @if($errors->has('scanName')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md" placeholder="@if($errors->has('scanName')){{'Required'}}@else{{''}}@endif" 
                                aria-describedby="user-name"
                            >                                   
                            @if($errors->first('name'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('name') }}</p>
                            @endif
                        </dd>
                    </div>
                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Change Email
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <input 
                                wire:key="userEmail-Edit-0" 
                                type="text" 
                                wire:model.lazy="userEmail" 
                                name="email" 
                                placeholder="{{ $userEmail }}"
                                id="email" 
                                class="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm @if($errors->has('scanName')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md" placeholder="@if($errors->has('scanName')){{'Required'}}@else{{''}}@endif" 
                                aria-describedby="user-email"
                            >                                      
                            @if($errors->first('email'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('email') }}</p>
                            @endif
                        </dd>
                    </div>


                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Password Reset
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <select 
                                wire:key="togglePasswordReset-0" 
                                wire:model="togglePasswordReset" 
                                id="roles" 
                                name="roles" 
                                class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                            >
                               <option value="No">No</option>
                               <option value="Yes">Yes</option>
                            </select>                               
                            @if($errors->first('togglePasswordReset'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('togglePasswordReset') }}</p>
                            @endif
                        </dd>
                    </div>

                    @if($togglePasswordReset === 'Yes')
                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Reset Password
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <input 
                                wire:key="editPassword-0" 
                                type="password" 
                                wire:model.lazy="userPassword" 
                                name="password" 
                                id="password" 
                                placeholder="" 
                                class="block @if($errors->has('userPassword')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                aria-describedby="user-password"
                            >                                   
                            @if($errors->first('userPassword'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('userPassword') }}</p>
                            @endif
                        </dd>
                    </div>
                    @endif

                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Change Role
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <select 
                                wire:key="toggleChangeRole-0" 
                                wire:model="toggleChangeRole" 
                                id="roles" 
                                name="roles" 
                                class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                            >
                               <option value="No">No</option>
                               <option value="Yes">Yes</option>
                            </select>                               
                            @if($errors->first('toggleChangeRole'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('toggleChangeRole') }}</p>
                            @endif
                        </dd>
                    </div>

                    @if($toggleChangeRole === 'Yes')
                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                        <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                            Select Role
                        </dt>
                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                            <select 
                                wire:key="roles-0" 
                                wire:model="userRoles" 
                                id="roles" 
                                name="roles" 
                                class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                            >
                                    <option value="" hidden selected>Roles...</option>
                                    @foreach($roles as $role)
                                        <option value="{{ $role->name }}">{{ $role->name }}</option>
                                    @endforeach
                            </select>                                  
                            @if($errors->first('role'))
                                <p class="mt-1 text-sm text-gray-500">{{ $errors->first('role') }}</p>
                            @endif
                        </dd>
                    </div>
                    @endif
                </dl>
            </div>
        </x-slot>

        <x-slot name="footer">
            <div class="flex justify-between">
                <x-jet-secondary-button wire:click="editModalClose" >
                    {{ __('Close') }}
                </x-jet-secondary-button>
    
                <x-jet-button wire:click="saveEditUser('{{ $userID }}')" >
                    {{ __('Save') }}
                </x-jet-button>
            </div>
        </x-slot>
    </x-jet-dialog-modal>

    {{-- Delete User Modal --}}
    <x-jet-dialog-modal wire:model.defer="modalDeleteUser" maxWidth="mds">
        <x-slot name="title">
            Delete User
        </x-slot>

        <x-slot name="content">
            <div class="mt-5 mb-5 sm:flex sm:items-start">
                <div class="flex items-center justify-center flex-shrink-0 w-12 h-12 mx-auto bg-red-100 rounded-full sm:mx-0 sm:h-10 sm:w-10">
                    <!-- Heroicon name: outline/exclamation -->
                    <svg class="w-6 h-6 text-red-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                </div>
                <div class="mt-0 text-center sm:mt-0 sm:ml-4 sm:text-left">
                    <div class="mt-0">
                        <p class="text-gray-500">
                            Are you sure you want to delete this user?
                        </p>
                    </div>
                </div>
            </div>
        </x-slot>

        <x-slot name="footer">
            <div class="flex justify-between">
                <x-jet-secondary-button wire:click="deleteModalClose" >
                    {{ __('Close') }}
                </x-jet-secondary-button>
    
                <x-jet-danger-button wire:click="deleteUser('{{ $userID }}')" >
                    {{ __('Delete') }}
                </x-jet-danger-button>
            </div>
        </x-slot>
    </x-jet-dialog-modal>

    @if(session()->has('message'))
    <div x-data="{ show: true }" x-show="show" x-init="setTimeout(() => show = false, 3000)">
        <div aria-live="assertive" class="absolute inset-0 flex items-end w-full px-4 py-6 pointer-events-none sm:p-6 sm:items-start">
            <div class="flex flex-col items-center w-full space-y-4 sm:items-end">
                <div class="w-full max-w-sm overflow-hidden bg-white rounded-lg shadow-lg pointer-events-auto ring-1 ring-black ring-opacity-5">
                    <div class="p-4">
                        <div class="flex items-start">
                            <div class="flex-shrink-0">
                                <svg class="w-6 h-6 text-green-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" aria-hidden="true">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                            </div>
                            <div class="ml-3 w-0 flex-1 pt-0.5">
                                <p class="text-sm font-medium text-gray-900">{{ session('message') }}</p>
                                <p class="mt-1 text-sm text-gray-500">User can now log into the application.</p>
                            </div>
                            <div class="flex flex-shrink-0 ml-4">
                                <button type="button" class="inline-flex text-gray-400 bg-white rounded-md hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                                    <span class="sr-only">Close</span>
                                    <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                                    </svg>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endif
    
</div>


