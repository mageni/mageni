<div>
    <x-headers.scan />
    <main class="py-10">
        @if(env('APP_ENV') === 'demo')
            <div class="max-w-full mx-auto mb-4 -mt-4 sm:px-6 lg:px-6">
                <div class="p-4 bg-indigo-600 rounded-md">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <!-- Heroicon name: solid/information-circle -->
                            <svg class="w-5 h-5 text-white" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="flex-1 ml-3 md:flex md:justify-between">
                            <p class="text-sm text-white">
                                Thanks for using the Live Demo. Some features are disabled on purpose to prevent accidental scans.
                            </p>
                            <p class="mt-3 text-sm md:mt-0 md:ml-6">
                                <a href="{{ env("STRIPE_URL") }}" target="_blank" class="font-medium text-white whitespace-nowrap hover:text-indigo-50">Get Started For Free <span aria-hidden="true">&rarr;</span></a>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        @endif

        <x-notification />

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
            
            <div>
                <h3 class="text-lg font-medium leading-6 text-gray-900">Scans</h3>
                <dl class="grid grid-cols-1 gap-5 mt-5 sm:grid-cols-4">
                    <div class="px-4 py-5 overflow-hidden bg-white rounded-lg shadow sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Total</dt>
                        @if($scansAll > 0)
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">{{ $scansAll }}</dd>
                        @else
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">0</dd>
                        @endif
                    </div>
                
                    <div class="px-4 py-5 overflow-hidden bg-white rounded-lg shadow sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">New</dt>
                        @if($scansNew > 0)
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">{{ $scansNew }}</dd>
                        @else
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">0</dd>
                        @endif
                    </div>
                
                    <div class="px-4 py-5 overflow-hidden bg-white rounded-lg shadow sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Completed</dt>
                        @if($scansCompleted > 0)
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">{{ $scansCompleted }}</dd>
                        @else
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">0</dd>
                        @endif
                    </div>

                    <div class="px-4 py-5 overflow-hidden bg-white rounded-lg shadow sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Running</dt>
                        @if($scansRunning > 0)
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">{{ $scansRunning }}</dd>
                        @else
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">0</dd>
                        @endif
                    </div>
                </dl>
            </div>
                                                                
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
                                placeholder="Search"/>
                            <x-button.link
                                class="py-3 ml-4 text-indigo-600 hover:text-indigo-500"
                                wire:click="$toggle('showFilters')">
                                @if ($showFilters) Hide @endif Advanced Search
                            </x-button.link>
                        </div>
                        <div class="flex justify-between space-x-2">
                            <div>
                                @if($selectPage || $selected)
                                    <div>
                                        <x-jet-button wire:click="$toggle('showDeleteModal')" class="hover:shadow">
                                            Delete Scans
                                        </x-jet-button>
                                    </div>
                                @endif
                            </div>
                            
                            <x-jet-button
                                wire:click="newScanModal" 
                                class="hover:shadow"
                            >
                                New Scan
                            </x-jet-button>
                            
                        </div>
                    </div>
                    <div>
                        @if ($showFilters)
                            <div class="relative flex p-4 bg-white border border-gray-200 rounded shadow-inner">
                                <div class="w-1/2 pr-2 space-y-4">
                                    <x-input.group inline for="filter-status" label="Status">
                                        <x-input.select wire:model="filters.run_status" id="filter-status">
                                            <option value="" disabled>Select Status...</option>
                                            @foreach (App\Models\Task::STATUSES as $value => $label)
                                                <option value="{{ $value }}">{{ $label }}</option>
                                            @endforeach
                                        </x-input.select>
                                    </x-input.group>

{{--                                    @json($filters);--}}
{{--                                    @json($selected);--}}
                                </div>

{{--                                <div class="w-1/2 pl-2 space-y-4">--}}
{{--                                    <x-input.group inline for="filter-date-min" label="Minimum Date">--}}
{{--                                        <x-input.date wire:model="filters.date-min" id="filter-date-min" placeholder="MM/DD/YYYY" />--}}
{{--                                    </x-input.group>--}}

{{--                                    <x-input.group inline for="filter-date-max" label="Maximum Date">--}}
{{--                                        <x-input.date wire:model="filters.date-max" id="filter-date-max" placeholder="MM/DD/YYYY" />--}}
{{--                                    </x-input.group>--}}

{{--                                    <x-button.link wire:click="resetFilters" class="absolute bottom-0 right-0 p-4">Reset Filters</x-button.link>--}}
{{--                                </div>--}}
                            </div>
                        @endif
                    </div>
                    <div>
                        @if($stopPolling == 'No')
                            <div class="flex-col space-y-4" wire:poll.keep-alive.10000ms>
                        @elseif($stopPolling == 'Yes')
                            <div class="flex-col space-y-4">
                        @endif
                    </div>
                    @json($selected)
                    <x-table class="table-auto">
                        <x-slot name="head">
                            <x-table.heading class="w-6 pr-0">
                                <x-input.checkbox wire:model="selectPage" class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"/>
                            </x-table.heading>
                            <x-table.heading sortable wire:click="sortBy('name')" :direction="$sortField === 'name' ? $sortDirection : null">Name</x-table.heading>
                            <x-table.heading sortable wire:click="sortBy('run_status')" :direction="$sortField === 'run_status' ? $sortDirection : null">Status</x-table.heading>
                            <x-table.heading sortable wire:click="sortBy('schedule')" :direction="$sortField === 'schedule' ? $sortDirection : null">Automatic Run  </x-table.heading>
                            <x-table.heading sortable wire:click="sortBy('creation_time')" :direction="$sortField === 'creation_time' ? $sortDirection : null">Created</x-table.heading>
                            <x-table.heading sortable wire:click="sortBy('modification_time')" :direction="$sortField === 'creation_time' ? $sortDirection : null">Modified</x-table.heading>
                            <x-table.heading sortable></x-table.heading>
                        </x-slot>
                        <x-slot name="body">
                            <div>
                                @if($selectPage || $selected)
                                    <x-table.row class="bg-gray-200" wire:key="row-message">
                                        <x-table.cell colspan="100%">
                                            @unless($selectAll)
                                                <div>
                                                    <span>You have selected <strong>{{ count($selected) }}</strong> tasks, do you want select all <strong>{{ $scans->total() }}</strong>?</span>
                                                    <x-button.link wire:click="selectAll" class="ml-1 text-blue-500">Select All</x-button.link>
                                                </div>
                                            @else
                                                <div>
                                                    <span>You have selected all <strong>{{ $scans->total() }}</strong> tasks. <x-button.link wire:click="unSelectAll" class="ml-1 text-blue-500">UnSelect All</x-button.link></span>
                                                </div>
                                            @endif
                                        </x-table.cell>
                                    </x-table.row>
                                @endif
                            </div>
                            <div>
                                @if($scans->count() > 0)
                                    @foreach($scans as $scan)
                                        <x-table.row wire:loading.delay.class="opacity-50" wire:target="search">
                                            <x-table.cell class="pr-0">
                                                <div wire:key="{{ $loop->index }}">
                                                    @if($scan->run_status == 4 || $scan->run_status == 3)
                                                        <input wire:key="{{ $loop->index }}" id="tasks" aria-describedby="checkbox" name="checkbox" type="checkbox" class="w-4 h-4 text-blue-600 border-gray-300 rounded cursor-not-allowed focus:ring-blue-500" disabled>
                                                    @else
                                                        <input wire:key="{{ $loop->index }}" wire:model="selected" value="{{ $scan->id }}" id="tasks" aria-describedby="tasks-id" name="tasks" type="checkbox" class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500">
                                                    @endif
                                                </div>
                                            </x-table.cell>
                                            <x-table.cell>
                                                <div class="flex items-center space-x-3" wire:key="{{ $loop->index }}">
                                                    <div wire:key="{{ $loop->index }}">
                                                        @if($scan->run_status == 1)
                                                        <span wire:key="{{ $loop->index }}" class="flex items-center justify-center w-4 h-4 bg-green-100 rounded-full animate-pulse" aria-hidden="true">
                                                            <span class="w-2 h-2 bg-green-700 rounded-full"></span>
                                                        </span>
                                                        @elseif($scan->run_status == 2)
                                                        <span wire:key="{{ $loop->index }}" class="flex items-center justify-center w-4 h-4 bg-indigo-100 rounded-full animate-pulse" aria-hidden="true">
                                                            <span class="w-2 h-2 bg-indigo-400 rounded-full"></span>
                                                        </span>
                                                        @elseif($scan->run_status == 3)
                                                        <span wire:key="{{ $loop->index }}" class="flex items-center justify-center w-4 h-4 bg-yellow-100 rounded-full animate-pulse" aria-hidden="true">
                                                            <span class="w-2 h-2 bg-yellow-400 rounded-full"></span>
                                                        </span>
                                                        @elseif($scan->run_status == 4)
                                                        <span wire:key="{{ $loop->index }}" class="flex items-center justify-center w-4 h-4 bg-blue-100 rounded-full animate-pulse" aria-hidden="true">
                                                            <span class="w-2 h-2 bg-green-500 rounded-full"></span>
                                                        </span>
                                                        @elseif($scan->run_status == 10 || $scan->run_status == 11)
                                                        <span wire:key="{{ $loop->index }}" class="flex items-center justify-center w-4 h-4 bg-red-100 rounded-full animate-pulse" aria-hidden="true">
                                                            <span class="w-2 h-2 bg-red-400 rounded-full"></span>
                                                        </span>
                                                        @elseif($scan->run_status == 12)
                                                        <span wire:key="{{ $loop->index }}" class="flex items-center justify-center w-4 h-4 bg-red-100 rounded-full animate-pulse" aria-hidden="true">
                                                            <span class="w-2 h-2 bg-red-400 rounded-full"></span>
                                                        </span>
                                                        @elseif($scan->run_status == 13)
                                                        <span wire:key="{{ $loop->index }}" class="flex items-center justify-center w-4 h-4 bg-red-300 rounded-full animate-pulse" aria-hidden="true">
                                                            <span class="w-2 h-2 bg-red-800 rounded-full"></span>
                                                        </span>
                                                        @elseif($scan->run_status == 18)
                                                        <span wire:key="{{ $loop->index }}" class="flex items-center justify-center w-4 h-4 bg-red-300 rounded-full animate-pulse" aria-hidden="true">
                                                            <span class="w-2 h-2 bg-gray-800 rounded-full"></span>
                                                        </span>
                                                        @endif
                                                    </div>
                                                    <h2 wire:key="{{ $loop->index }}" class="flex text-sm justify-self-auto">
                                                        <x-button.link 
                                                            wire:key="{{ $loop->index }}" 
                                                            wire:click="scanDetails('{{$scan->id}}')"
                                                            class="font-semibold text-gray-500 hover:text-indigo-700">
                                                                {{ $scan->name }}
                                                        </x-button.link>
                                                    </h2>
                                                </div>
                                            </x-table.cell>
                                            <x-table.cell>
                                                <div wire:key="{{ $loop->index }}">
                                                    @if($scan->run_status == 1)
                                                    <span wire:key="{{ $loop->index }}" class="inline-flex px-2 text-xs font-semibold leading-5 text-green-700 border border-green-700 rounded-full bord">
                                                        Completed
                                                    </span>
                                                    @elseif($scan->run_status == 2)
                                                    <span wire:key="{{ $loop->index }}" class="inline-flex px-2 text-xs font-semibold leading-5 text-indigo-600 border border-indigo-600 rounded-full">
                                                        New
                                                    </span>
                                                    @elseif($scan->run_status == 3)
                                                    <span wire:key="{{ $loop->index }}" class="inline-flex px-2 text-xs font-semibold leading-5 text-yellow-600 border border-yellow-600 rounded-full">
                                                      Starting
                                                    </span>
                                                    @elseif($scan->run_status == 4)
                                                    <span wire:key="{{ $loop->index }}" class="inline-flex px-2 text-xs font-semibold leading-5 text-green-500 border border-green-500 rounded-full">
                                                        Running
                                                    </span>
                                                    @elseif($scan->run_status == 10 || $scan->run_status == 11)
                                                    <span wire:key="{{ $loop->index }}" class="inline-flex px-2 text-xs font-semibold leading-5 text-red-700 border border-red-700 rounded-full">
                                                        Stopping
                                                    </span>
                                                    @elseif($scan->run_status == 12)
                                                    <span wire:key="{{ $loop->index }}" class="inline-flex px-2 text-xs font-semibold leading-5 text-red-700 border border-red-700 rounded-full">
                                                        Stopped
                                                    </span>
                                                    @elseif($scan->run_status == 13)
                                                    <span wire:key="{{ $loop->index }}" class="inline-flex px-2 text-xs font-semibold leading-5 text-red-700 border border-red-700 rounded-full">
                                                        Interrupted
                                                    </span>
                                                    @elseif($scan->run_status == 15)
                                                    <span wire:key="{{ $loop->index }}" class="inline-flex px-2 text-xs font-semibold leading-5 text-gray-700 border border-gray-700 rounded-full">
                                                        Stop Requested Error
                                                    </span>
                                                    @endif
                                                </div>
                                            </x-table.cell>
                                            <x-table.cell>
                                                <div wire:key="{{ $loop->index }}">
                                                    <span wire:key="{{ $loop->index }}">
                                                        @if($scan->schedule == 0)
                                                            <span 
                                                                wire:key="{{ $loop->index }}" 
                                                                class="inline-flex px-2 text-xs font-semibold leading-5 text-zinc-500 rounded-full border border-zinc-500"
                                                            >
                                                                {{ 'No' }}
                                                            </span>
                                                        @else
                                                            @if(isset($scan->schedule_next_time) && !Str::contains($scan->schedule_next_time, '1970'))
                                                                <span 
                                                                    wire:key="{{ $loop->index }}" 
                                                                    class="inline-flex px-2 text-xs font-semibold leading-5 text-blue-500 border border-blue-500 rounded-full"
                                                                >
                                                                    {{ $scan->schedule_next_time->diffForHumans() }}
                                                                </span>
                                                            @endif
                                                        @endif
                                                    </span>
                                                </div>
                                            </x-table.cell>
                                            <x-table.cell>
                                                <div wire:key="{{ $loop->index }}">
                                                    <span>{{ $scan->creation_time->diffForHumans() }}</span>
                                                </div>
                                            </x-table.cell>
                                            <x-table.cell>
                                                <div wire:key="{{ $loop->index }}" class="inline-flex space-x-2 text-sm leading-5 truncate">
                                                    <span wire:key="{{ $loop->index }}">
                                                        {{ $scan->modification_time->diffForHumans() }}
                                                    </span>
                                                </div>
                                            </x-table.cell>
                                            <x-table.cell>
                                                <div class="flex flex-row justify-end space-x-3">
                                                    <div class="py-1 sm:py-1 sm:grid sm:grid-cols-6 sm:gap-2">
                                                        <div>
                                                            @if($scan->run_status == 2 or $scan->run_status == 1)
                                                                @if(env('APP_ENV') === 'production')
                                                                    @if($scan->hidden == 0)
                                                                        <div>
                                                                            <i 
                                                                                wire:key="{{ $loop->index }}" 
                                                                                wire:click="taskStart('{{$scan->uuid}}')" 
                                                                                class="ml-1 text-green-600 cursor-pointer far fa-solid fa-play-circle fa-lg hover:text-green-700"
                                                                                x-data
                                                                                x-tooltip="Start Scan"
                                                                            >
                                                                            </i>
                                                                        </div>
                                                                    @elseif($scan->hidden == 2)
                                                                        <div>
                                                                            <i 
                                                                                wire:key="{{ $loop->index }}" 
                                                                                class="ml-1 text-indigo-300 cursor-not-allowed far fa-play-circle fa-lg" 
                                                                                x-data
                                                                                x-tooltip="Scan Locked"
                                                                            >
                                                                            </i>
                                                                        </div>
                                                                    @endif
                                                                @elseif(env('APP_ENV') === 'demo')
                                                                        <div>
                                                                            <i 
                                                                                wire:key="{{ $loop->index }}" 
                                                                                class="ml-1 text-green-300 cursor-not-allowed far fa-play-circle fa-lg hover:text-green-500" 
                                                                                x-data
                                                                                x-tooltip="Scan Disabled"
                                                                            >
                                                                            </i>
                                                                        </div>
                                                                @endif
                                                            @elseif($scan->run_status == 4)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            wire:click="taskStop('{{$scan->uuid}}')" 
                                                                            class="ml-1 text-red-600 cursor-pointer far fa-pause-circle fa-lg hover:text-red-800" 
                                                                            x-data
                                                                            x-tooltip="Stop Scan"
                                                                            >
                                                                        </i>
                                                                    </div>
                                                            @elseif($scan->run_status == 12 || $scan->run_status == 13)
                                                                @if($scan->hidden == 0)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            wire:click="taskResume('{{$scan->uuid}}')" 
                                                                            class="ml-1 text-blue-600 cursor-pointer fas fa-redo-alt fa-lg hover:text-blue-900" 
                                                                            x-data
                                                                            x-tooltip="Restart Scan"
                                                                        >
                                                                        </i>
                                                                    </div>
                                                                @elseif($scan->hidden == 2)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            class="ml-1 text-indigo-300 cursor-not-allowed fas fa-redo-alt fa-lg" 
                                                                            x-data
                                                                            x-tooltip="Restart Scan"
                                                                        >
                                                                        </i>
                                                                    </div>
                                                                @endif
                                                            @elseif($scan->run_status == 3 or $scan->run_status == 0 or $scan->run_status == 14 or $scan->run_status == 10 or $scan->run_status == 11)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            class="ml-1 fas fa-spinner fa-lg animate-spin"
                                                                        >
                                                                        </i>
                                                                    </div>
                                                            @endif
                                                        </div>
                                                        <div class="space-x-3">
                                                            <div>
                                                            @if($scan->run_status == 0 || $scan->run_status == 3 || $scan->run_status == 4 || $scan->run_status == 10 || $scan->run_status == 11 || $scan->run_status == 14 || $scan->run_status == 15 || $scan->run_status == 16 || $scan->run_status == 17)
                                                                <div>
                                                                    <i 
                                                                        wire:key="{{ $loop->index }}" 
                                                                        class="text-indigo-300 cursor-not-allowed fas fa-pencil-alt fa-lg" 
                                                                        x-data
                                                                        x-tooltip="Edit Scan"
                                                                    >
                                                                    </i>
                                                                </div>
                                                            @else
                                                                @if(env('APP_ENV') === 'demo')
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            class="text-blue-600 cursor-not-allowed fas fa-pencil-alt fa-lg hover:text-blue-900" 
                                                                            x-data
                                                                            x-tooltip="Edit Scan"
                                                                        >
                                                                        </i>
                                                                    </div>
                                                                @else
                                                                    @if($scan->hidden == 0)
                                                                        <div>
                                                                            <i 
                                                                                wire:key="{{ $loop->index }}" 
                                                                                wire:click="edit('{{$scan->id}}')" 
                                                                                class="text-blue-600 cursor-pointer fas fa-pencil-alt fa-lg hover:text-blue-900" 
                                                                                x-data
                                                                                x-tooltip="Edit Scan"
                                                                            >
                                                                            </i>
                                                                        </div>
                                                                    @elseif($scan->hidden == 2)
                                                                        <div>
                                                                            <i 
                                                                                wire:key="{{ $loop->index }}" 
                                                                                class="text-indigo-300 cursor-not-allowed fas fa-pencil-alt fa-lg" 
                                                                                x-data
                                                                                x-tooltip="Edit Scan" 
                                                                            >
                                                                            </i>
                                                                        </div> 
                                                                    @endif
                                                                @endif
                                                            @endif
                                                            </div>
                                                        </div>
                                                        <div>
                                                            @if($scan->run_status == 0 || $scan->run_status == 3 || $scan->run_status == 4 || $scan->run_status == 10 || $scan->run_status == 11 || $scan->run_status == 14 || $scan->run_status == 15 || $scan->run_status == 16 || $scan->run_status == 17)
                                                                <div>
                                                                    <i 
                                                                        wire:key="{{ $loop->index }}" 
                                                                        class="text-indigo-300 cursor-not-allowed fas fa-copy fa-lg" 
                                                                        x-data
                                                                        x-tooltip="Clone Scan" 
                                                                    >
                                                                    </i>
                                                                </div>
                                                            @else
                                                                @if($scan->hidden == 0)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            wire:click="taskClone('{{$scan->uuid}}')" 
                                                                            class="text-indigo-500 cursor-pointer fas fa-copy fa-lg hover:text-indigo-900" 
                                                                            x-data
                                                                            x-tooltip="Clone Scan" 
                                                                        >
                                                                        </i>
                                                                    </div>
                                                                @elseif($scan->hidden == 2)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            class="text-indigo-300 cursor-not-allowed fas fa-copy fa-lg" 
                                                                            x-data
                                                                            x-tooltip="Clone Scan"
                                                                        >
                                                                        </i>
                                                                    </div>
                                                                @endif
                                                            @endif
                                                        </div>
                                                        <div>
                                                            @if($scan->run_status == 0 || $scan->run_status == 3 || $scan->run_status == 4 || $scan->run_status == 10 || $scan->run_status == 11 || $scan->run_status == 14 || $scan->run_status == 15 || $scan->run_status == 16 || $scan->run_status == 17)
                                                                <div>
                                                                    <i  
                                                                        wire:key="{{ $loop->index }}" 
                                                                        class="text-indigo-300 cursor-not-allowed fas fa-lock fa-lg" 
                                                                        x-data
                                                                        x-tooltip="Unlock Scan"
                                                                    >
                                                                    </i>
                                                                </div>
                                                            @else
                                                                @if($scan->hidden == 0)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            wire:click="taskLock('{{$scan->uuid}}')" 
                                                                            class="text-indigo-500 cursor-pointer fas fa-lock-open fa-lg hover:text-indigo-900" 
                                                                            x-data
                                                                            x-tooltip="Lock Scan"
                                                                        >
                                                                        </i>
                                                                    </div>
                                                                @elseif($scan->hidden == 2)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            wire:click="taskUnlock('{{$scan->uuid}}')" 
                                                                            class="text-indigo-500 cursor-pointer fas fa-lock fa-lg hover:text-indigo-900" 
                                                                            x-data
                                                                            x-tooltip="Unlock Scan"
                                                                        >
                                                                        </i>
                                                                    </div>
                                                                @endif
                                                            @endif
                                                        </div>
                                                        <div>
                                                            @if($scan->run_status == 0 || $scan->run_status == 3 || $scan->run_status == 4 || $scan->run_status == 10 || $scan->run_status == 11 || $scan->run_status == 14 || $scan->run_status == 15 || $scan->run_status == 16 || $scan->run_status == 17)
                                                                <i 
                                                                    wire:key="{{ $loop->index }}" 
                                                                    class="text-indigo-300 cursor-not-allowed fas fa-regular fa-file-export fa-lg" 
                                                                    x-data
                                                                    x-tooltip="Export Report"
                                                                >
                                                                </i>
                                                            @else
                                                                <i 
                                                                    wire:key="{{ $loop->index }}" 
                                                                    wire:click="exportLastReport('{{$scan->id}}')" 
                                                                    class="text-indigo-500 cursor-pointer fas fa-regular fa-file-export fa-lg hover:text-indigo-900" 
                                                                    x-data
                                                                    x-tooltip="Export Report"
                                                                >
                                                                </i>
                                                            @endif
                                                        </div>
                                                        <div>
                                                            @if(env('APP_ENV') === 'production')
                                                                @if($scan->run_status == 0 || $scan->run_status == 3 || $scan->run_status == 4 || $scan->run_status == 10 || $scan->run_status == 11 || $scan->run_status == 14 || $scan->run_status == 15 || $scan->run_status == 16 || $scan->run_status == 17)
                                                                    <div>
                                                                        <i 
                                                                            wire:key="{{ $loop->index }}" 
                                                                            class="text-indigo-300 cursor-not-allowed far fa-trash-alt fa-lg" 
                                                                            x-data
                                                                            x-tooltip="Delete Scan"
                                                                        >
                                                                        </i>
                                                                    </div>
                                                                @else
                                                                    @if($scan->hidden == 0)
                                                                        <div>
                                                                            <i 
                                                                                wire:key="{{ $loop->index }}" 
                                                                                wire:click="deleteShowModal('{{$scan->uuid}}')" 
                                                                                class="text-red-600 cursor-pointer far fa-trash-alt fa-lg hover:text-red-900" 
                                                                                x-data
                                                                                x-tooltip="Delete Scan"
                                                                            >
                                                                            </i>
                                                                        </div>
                                                                    @elseif($scan->hidden == 2)
                                                                        <div>
                                                                            <i 
                                                                                wire:key="{{ $loop->index }}" 
                                                                                class="text-indigo-300 cursor-not-allowed far fa-trash-alt fa-lg" 
                                                                                x-data
                                                                                x-tooltip="Delete Scan"
                                                                            >
                                                                            </i>
                                                                        </div>
                                                                    @endif
                                                                @endif
                                                            @elseif(env('APP_ENV') === 'demo')
                                                                <div>
                                                                    <i 
                                                                        wire:key="{{ $loop->index }}" 
                                                                        id="myButton" 
                                                                        x-data
                                                                        x-tooltip="Delete Scan"
                                                                    >
                                                                    </i>
                                                                </div>
                                                            @endif
                                                        </div>
                                                    </div>
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
                                            No scans found.
                                        </span>
                                    </x-table.cell>
                                </x-table.row>
                            @endif
                        </x-slot>
                    </x-table>
                    <div class="mt-2">
                        {{ $scans->links() }}
                    </div>
                    </div>
                </div>

                {{-- Modal Create Scan --}}
                <x-jet-dialog-modal wire:key="createModal-0" wire:model="modalFormVisible" maxWidth="mds">
                    <x-slot name="title">
                        <div class="flex items-center justify-between">
                            <div>
                                {{ $pages[$currentPage]['heading'] }}
                                <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                    {{ $pages[$currentPage]['subheading'] }}
                                </p>
                            </div>
                            <div 
                                x-data
                                x-tooltip="Close"
                                wire:click="closeShowModal" 
                                wire:key="closeCreateScanModalButton-0">
                                <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-gray-500 cursor-pointer hover:text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                            </div>
                        </div>
                    </x-slot>

                    <x-slot name="content">
                        <nav aria-label="Progress">
                            <ol role="list" class="pt-2 pb-2 space-y-4 md:flex md:space-y-0 md:space-x-8">
                                <li class="md:flex-1">
                                    <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage === 1){{'blue-400 animate-pulse'}}@elseif($currentPage >= 2){{'blue-700'}}@endif hover:border-indigo-800 md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                        <span class="text-xs font-semibold tracking-wide text-indigo-600 uppercase group-hover:text-indigo-800">Step 1</span>
                                        <span class="text-sm font-medium">Template</span>
                                    </a>
                                </li>

                                <li class="md:flex-1">
                                    <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage < 2){{'gray-200'}}@elseif($currentPage === 2){{'blue-400 animate-pulse'}}@elseif($currentPage >= 2){{'blue-700'}}@endif hover:border-gray-300 md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                        <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 2</span>
                                        <span class="text-sm font-medium">Targets</span>
                                    </a>
                                </li>

                                <li class="md:flex-1">
                                    <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage <= 2){{'gray-200'}}@elseif($currentPage === 3){{'indigo-400 animate-pulse'}}@elseif($currentPage >= 4){{'indigo-700'}}@endif  hover:border-gray-300 md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                        <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 3</span>
                                        <span class="text-sm font-medium">Credentials</span>
                                    </a>
                                </li>

                                <li class="md:flex-1">
                                    <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage <= 3){{'gray-200'}}@elseif($currentPage === 4){{'blue-400 animate-pulse'}}@elseif($currentPage >= 5){{'blue-700'}}@endif hover:border-blue-400 hover:animate-pulse md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                        <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 4</span>
                                        <span class="text-sm font-medium">Schedules</span>
                                    </a>
                                </li>
                                
                                <li class="md:flex-1">
                                    <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage <= 4){{'gray-200'}}@elseif($currentPage === 5){{'blue-400 animate-pulse'}}@elseif($currentPage === 6){{'blue-700'}}@endif hover:border-blue-400 hover:animate-pulse md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                        <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 5</span>
                                        <span class="text-sm font-medium">Notifications</span>
                                    </a>
                                </li>

                                <li class="md:flex-1">
                                    <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage <= 5){{'gray-200'}}@elseif($currentPage === 6){{'blue-400 animate-pulse'}}@endif hover:border-gray-300 md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                        <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 6</span>
                                        <span class="text-sm font-medium">Review</span>
                                    </a>
                                </li>
                            </ol>
                        </nav>

                        @if($currentPage === 1)
                        {{-- Page 1 Starts --}}
                        
                        <div class="px-4 py-5 mt-2 border-t border-gray-200 sm:p-0">
                            <dl class="sm:divide-y sm:divide-gray-200">
                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                    <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                                        Name
                                    </dt>
                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                        <input 
                                            wire:key="scanName-12" 
                                            type="text" 
                                            wire:model.lazy="scanName" 
                                            name="name" 
                                            id="name" 
                                            class="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm @if($errors->has('scanName')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md" placeholder="@if($errors->has('scanName')){{'Required'}}@else{{''}}@endif" 
                                            aria-describedby="scan-name"
                                        >                                      
                                        @if($errors->first('scanName'))
                                            <p class="mt-1 text-sm text-gray-500">{{ $errors->first('scanName') }}</p>
                                        @elseif(!$errors->first('scanName') && $scanName != "")
                                            <div class="flex flex-row mt-2 space-x-1">
                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                </svg>
                                                <p class="text-sm text-gray-500">Scan name has been set</p>
                                            </div>
                                        @else 
                                            <p class="mt-1 text-sm text-gray-500">Required</p>
                                        @endif
                                    </dd>
                                </div><div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                    <dt class="mt-8 text-sm font-medium text-gray-500">
                                        Description
                                    </dt>
                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                        <textarea 
                                            wire:key="scanDescription-12" 
                                            wire:model.lazy="scanDescription" 
                                            id="scanDescription" 
                                            name="scanDescription" 
                                            rows="3" 
                                            class="block max-w-xl border @if($errors->has('scanDescription')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm w-full focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" placeholder="@if($errors->has('scanDescription')){{'Required'}}@else{{''}}@endif">
                                        </textarea>
                                        @if($errors->first('scanDescription'))
                                            <p class="mt-1 text-sm text-gray-500">{{ $errors->first('scanDescription') }}</p>
                                        @elseif(!$errors->first('scanDescription') && $scanDescription != "")
                                            <div class="flex flex-row mt-2 space-x-1">
                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                </svg>
                                                <p class="text-sm text-gray-500">Description has been set</p>
                                            </div>
                                        @else 
                                            <p class="mt-1 text-sm text-gray-500">Required</p>
                                        @endif
                                    </dd>
                                </div>
                            </dl>
                        </div>

                        {{-- Scan Config Starts --}}
                        <div class="flex flex-col items-center py-4 mt-2 lg:flex-row sm:border-t sm:border-gray-200 sm:pt-4">
                            <fieldset>
                                @if($scanConfigID == "")
                                    @if($errors->first('scanConfigID'))
                                        <x-jet-label class="flex items-start justify-start mb-2" for="name" value="Please Select a Scan Policy" />
                                    @else
                                        <x-jet-label class="flex items-start justify-start mb-2" for="name" value="Select Scan Policy" />
                                    @endif
                                @else
                                    <div class="flex items-center mb-2">
                                        <svg class="w-5 h-5 text-green-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                        </svg>
                                        <p class="ml-2 text-sm font-medium text-gray-500">Scan Policy Selected</p>
                                    </div>
                                @endif
                                    <div class="grid grid-cols-1 gap-4 -space-y-px bg-white rounded-md sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
                                        @foreach($configs as $config)
                                            <label class="relative flex p-4 border @if($errors->has('scanConfigID')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded cursor-pointer hover:bg-gray-50 hover:border-indigo-500 rounded-tl-md">
                                                <input 
                                                    wire:key="scanConfigID-0" 
                                                    wire:model.lazy="scanConfigID" 
                                                    value="{{ $config->uuid }}" 
                                                    type="radio" 
                                                    name="scan-template" 
                                                    class="h-4 w-4 mt-0.5 cursor-pointer text-indigo-600 border-gray-300 focus:ring-indigo-500" 
                                                    aria-labelledby="scan-template-0-label" 
                                                    aria-describedby="scan-template-0-description"
                                                >
                                                <div class="flex flex-col ml-3">
                                                    <span id="privacy-setting-0-label" class="block text-sm font-medium text-gray-900">
                                                        {{ $config->name }}
                                                    </span>
                                                    <span id="privacy-setting-0-description" class="block text-sm text-gray-500">
                                                        {{ $config->comment }}
                                                    </span>
                                                </div>
                                            </label>
                                        @endforeach
                                    </div>
                            </fieldset>
                        </div>
                        {{-- Scan Config Ends --}}

                        {{-- Page 1 Ends --}}
                        @elseif($currentPage === 2)

                        {{-- Page 2 Starts --}}
                        
                        {{-- Targets Include/Exclude Starts --}}
                        <div class="py-5">
                            <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                <div class="sm:col-span-1">
                                    {{-- Handle Messages --}}
                                    @if(!$errors->first('targetList') && $targetList != "") 
                                        <dt class="text-sm font-medium text-gray-500">
                                            Include Targets
                                        </dt>
                                        <div class="flex flex-row flex-shrink-0 mt-2 space-x-2">
                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                            </svg>
                                            <dd class="text-sm text-gray-900">Assets configured</dd>
                                        </div>
                                    @elseif($errors->first('targetList')) 
                                        <dt class="text-sm font-medium text-gray-500">
                                            Exclude Targets
                                        </dt>
                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                            <svg class="w-5 h-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                                                </svg>
                                            <dd class="text-sm text-gray-900">Errors in assets</dd>
                                        </div>
                                    @else
                                        <dt class="text-sm font-medium text-gray-500">
                                            Include Targets
                                        </dt>
                                        <div class="flex flex-row flex-shrink-0 mt-2 space-x-2">
                                            <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                            </svg>
                                            <dd class="text-sm text-gray-900">No assets configured</dd>
                                        </div>
                                    @endif
                                </div>
                                <div class="sm:col-span-1">
                                    <textarea 
                                        wire:key="targetList-0" 
                                        wire:model.lazy="targetList" 
                                        id="targetList" 
                                        name="targetList" 
                                        rows="3" 
                                        class="block max-w-xl border border-gray-300 rounded-md shadow-sm w-80 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                    </textarea>
                                    {{-- Handle Errors --}}
                                    @if($errors->first('targetList'))
                                        <div class="flex flex-row py-1 space-x-1">
                                            <div class="flex-shrink-0">
                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                </svg>
                                            </div>
                                            <p class="text-sm text-red-500">
                                                {{ $errors->first('targetList') }}
                                            </p>
                                        </div>
                                    @endif
                                </div>
                                <div class="sm:col-span-1">
                                    <dt class="mt-4 text-sm font-medium text-gray-500">
                                        Do you want to exclude targets?
                                    </dt>
                                </div>
                                <div class="sm:col-span-1">
                                    <select 
                                        wire:key="toggleExcludeTargets-0" 
                                        wire:model="toggleExcludeTargets" 
                                        id="toggleExcludeTargets" 
                                        name="toggleExcludeTargets" 
                                        class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                    >
                                        <option value="No">No</option>
                                        <option value="Yes">Yes</option>
                                    </select>
                                </div>
                                @if($toggleExcludeTargets === 'Yes')
                                    <div class="sm:col-span-1">
                                        {{-- Message for users --}}
                                        @if(!$errors->first('targetExclude') && $targetExclude != $targetList && !is_null($targetExclude)) 
                                            <dt class="text-sm font-medium text-gray-500">
                                                Exclude Targets
                                            </dt>
                                            <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                </svg>
                                                <dd class="text-sm text-gray-900">Exclusion configured</dd>
                                            </div>
                                        @elseif($errors->first('targetExclude')) 
                                            <dt class="text-sm font-medium text-gray-500">
                                                Exclude Targets
                                            </dt>
                                            <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                <svg class="w-5 h-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                                                    </svg>
                                                <dd class="text-sm text-gray-900">Errors in exclusions</dd>
                                            </div>
                                        @else
                                            <dt class="text-sm font-medium text-gray-500">
                                                Exclude Targets
                                            </dt>
                                            <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                </svg>
                                                <dd class="text-sm text-gray-900">No exclusion configured</dd>
                                            </div>
                                        @endif
                                    </div>
                                    {{-- Text Area to Exclude Assets --}}
                                    <div class="sm:col-span-1">
                                        <textarea 
                                            wire:key="targetExclude-0" 
                                            wire:model.lazy="targetExclude" 
                                            id="targetExclude" 
                                            name="targetExclude" 
                                            rows="3" 
                                            class="block max-w-xl border border-gray-300 rounded-md shadow-sm w-80 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                        </textarea>
                                        {{-- Error from validation --}}
                                        @if($errors->first('targetExclude'))
                                            <div class="flex flex-row py-1 space-x-1">
                                                <div class="flex-shrink-0">
                                                    <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                    </svg>
                                                </div>
                                                <p class="text-sm text-red-500">
                                                    {{ $errors->first('targetExclude') }}
                                                </p>
                                            </div>
                                        @endif
                                    </div>
                                @endif
                            </dl>
                        </div>
                        {{-- Targets Include/Exclude Ends --}}

                        {{-- Port Scanning Starts --}}
                        <div class="mt-2 overflow-hidden bg-white sm:rounded-lg">
                            <div class="py-5">
                                <h3 class="text-lg font-medium leading-6 text-gray-900">
                                    Port Scanning
                                </h3>
                                <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                    A port scan is a method for determining which ports on a target are open.
                                </p>
                            </div>
                            <div class="py-5">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-1">
                                        @if($targetPorts != "customports" || $portRange != "") 
                                            <dt class="text-sm font-medium text-gray-500">
                                                Ports to Scan
                                            </dt>
                                            <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                </svg>
                                                <dd class="text-sm text-gray-900">Ports configured</dd>
                                            </div>
                                        @else
                                            <dt class="text-sm font-medium text-gray-500">
                                                Ports to Scan
                                            </dt>
                                            <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                </svg>
                                                <dd class="text-sm text-gray-900">Configure custom ports</dd>
                                            </div>
                                        @endif
                                    </div>
                                    <div class="sm:col-span-1">
                                        <select 
                                            wire:key="targetPorts-0" 
                                            wire:model="targetPorts" 
                                            id="location" 
                                            name="location" 
                                            class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                        >
                                            {{-- <option value="" hidden selected>Select Ports...</option> --}}
                                            <option value="fd591a34-56fd-11e1-9f27-406186ea4fc5">All TCP Ports from 1 to 65535</option>
                                            <option value="ab33f6b0-57f8-11e1-96f5-406186ea4fc5">Top TCP and UDP Ports</option>
                                            <option value="730ef368-57e2-11e1-a90f-406186ea4fc5">All TCP and Top 100 UDP Ports</option>
                                            <option value="customports">Custom</option>
                                        </select>
                                    </div>
                                </dl>
                                @if($targetPorts === 'customports')
                                    <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                        <div class="sm:col-span-1">
                                            <dt class="mt-12 text-sm font-medium text-gray-500">
                                                Custom Ports
                                            </dt>
                                        </div>
                                        <div class="sm:col-span-1">
                                            <div class="flex flex-col items-start py-4">
                                                <div class="flex flex-col py-4 lg:mr-3 lg:py-0">
                                                    <div class="sm:col-span-3">
                                                        <textarea 
                                                            wire:key="portRange-0" 
                                                            wire:model.lazy="portRange" 
                                                            placeholder="T:1-5,7,9,U:1-3,5,7,9" 
                                                            id="custom-ports" 
                                                            name="custom-ports" 
                                                            rows="3" 
                                                            class="block max-w-xl border border-gray-300 rounded-md shadow-sm w-80 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                                        </textarea>
                                                    </div>
                                                    @if($errors->first('portRange'))
                                                        <div class="flex flex-row py-1 space-x-1">
                                                            <div class="flex-shrink-0">
                                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                </svg>
                                                            </div>
                                                            <p class="text-sm text-red-500">
                                                                {{ $errors->first('portRange') }}
                                                            </p>
                                                        </div>
                                                    @endif
                                                </div>
                                            </div>
                                        </div>
                                    </dl>
                                @endif
                            </div>
                        </div>
                        {{-- Port Scanning Ends --}}

                        {{-- Host Discovery Method Starts --}}
                        <div class="mt-2 overflow-hidden bg-white sm:rounded-lg">
                            <div class="py-5">
                                <h3 class="text-lg font-medium leading-6 text-gray-900">
                                    Host Discovery Method
                                </h3>
                                <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                    Host discovery refers to network hosts' enumeration to gather information about the hosts.
                                </p>
                            </div>
                            <div class="py-5">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-1">
                                        @if($targetAlive != "") 
                                            <dt class="text-sm font-medium text-gray-500">
                                                Host Discovery
                                            </dt>
                                            <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                </svg>
                                                <dd class="text-sm text-gray-900">Discovery configured</dd>
                                            </div>
                                        @endif
                                    </div>
                                    <div class="sm:col-span-1">
                                        <select 
                                            wire:key="targetAlive-0" 
                                            wire:model="targetAlive" 
                                            id="location" 
                                            name="location" 
                                            class="block py-2 pl-3 pr-10 mt-1 text-base @if($errors->has('targetAlive')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                        >
                                            {{-- <option value="" hidden selected>Select Discovery Method...</option> --}}
                                            <option value="2">ICMP Ping</option>
                                            <option value="4">ARP Ping</option>
                                            <option value="7">ICMP, TCP-ACK Service & ARP Ping</option>
                                            <option value="3">ICMP & TCP-ACK Service Ping</option>
                                            <option value="8">Consider Alive</option>
                                            <option value="1">TCP-ACK Ping</option>
                                            <option value="16">TCP-SYN Ping</option>
                                            <option value="6">ICMP & ARP Ping</option>
                                            <option value="5">TCP-ACK & ARP Ping</option>
                                        </select>
                                    </div>
                                </dl>
                            </div>
                        </div>
                        {{-- Host Discovery Method Ends --}}

                        {{-- Performance Settings Starts --}}
                        <div class="mt-4 overflow-hidden bg-white sm:rounded-lg">
                            <div class="py-5">
                                <h3 class="text-lg font-medium leading-6 text-gray-900">
                                    Performance Settings
                                </h3>
                                <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                    Configure scan speed and number of concurrent tests and hosts.
                                </p>
                            </div>
                            <div class="py-5">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-1">
                                        @if($scanSpeed != "") 
                                            <dt class="text-sm font-medium text-gray-500">
                                                Scan Speed
                                            </dt>
                                            <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                </svg>
                                                <dd class="text-sm text-gray-900">Speed configured</dd>
                                            </div>
                                        @endif
                                    </div>
                                    <div class="sm:col-span-1">
                                        <select 
                                            wire:key="scanSpeed-0" 
                                            wire:model="scanSpeed" 
                                            id="scanSpeed" 
                                            name="scanSpeed" 
                                            class="block py-2 pl-3 pr-10 mt-1 text-base @if($errors->has('scanSpeed')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                        >
                                            {{-- <option value="" hidden selected>Select Speed...</option> --}}
                                            <option value="1">Slow</option>
                                            <option value="2">Normal</option>
                                            <option value="3">Fast</option>
                                        </select>
                                    </div>
                                </dl>
                            </div>
                        </div>
                        {{-- Performance Settings Ends --}}

                        {{-- Page 2 Ends --}}

                        @elseif($currentPage === 3)

                        {{-- Page 3 Starts --}}
                        
                        <div class="py-5">
                            <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                <div class="sm:col-span-1">
                                    
                                    @if($toggleSSHCredentials == "No") 
                                        <dt class="text-sm font-medium text-gray-500">
                                            SSH Credentials
                                        </dt>
                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                            <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                            </svg>
                                            <dd class="text-sm text-gray-900">No credentials configured</dd>
                                        </div>
                                    @elseif($toggleSSHCredentials == "Yes" && $credentialType == "up")
                                        <dt class="text-sm font-medium text-gray-500">
                                            SSH Credentials
                                        </dt>
                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                            @if(!$errors->first('sshLogin') && 
                                                !$errors->first('sshPassword') && 
                                                !empty($sshLogin) && 
                                                !empty($sshPassword)) 
                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                </svg>
                                            @else 
                                                <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                </svg>
                                            @endif
                                            <dd class="text-sm text-gray-900">
                                                @if(!$errors->first('sshLogin') && 
                                                    !$errors->first('sshPassword') && 
                                                    !empty($sshLogin) && 
                                                    !empty($sshPassword))
                                                    {{ 'Credentials provided' }} 
                                                @else 
                                                    {{ 'Please enter the credentials' }} 
                                                @endif
                                            </dd>
                                        </div>
                                    @elseif($toggleSSHCredentials == "Yes" && $credentialType == "usk")
                                        <dt class="text-sm font-medium text-gray-500">
                                            SSH Credentials
                                        </dt>
                                        <div class="flex flex-row flex-shrink-0 mt-2 space-x-2">
                                            @if(!$errors->first('sshLogin') && 
                                                !$errors->first('sshPhrase') && 
                                                !$errors->first('sshKey') &&
                                                !empty($sshLogin) && 
                                                !empty($sshPhrase) &&
                                                !empty($sshKey))
                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                </svg>
                                            @else
                                                <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                </svg>
                                            @endif
                                            <dd class="text-sm text-gray-900">
                                                @if(!$errors->first('sshLogin') && 
                                                    !$errors->first('sshPhrase') && 
                                                    !$errors->first('sshKey') &&
                                                    !empty($sshLogin) && 
                                                    !empty($sshPhrase) &&
                                                    !empty($sshKey)) 
                                                    {{ 'Credentials provided' }} 
                                                @else
                                                    {{ 'Please enter the credentials' }} 
                                                @endif
                                            </dd>
                                        </div>
                                    @endif
                                </div>
                                <div class="sm:col-span-1">
                                    <select 
                                        wire:key="toggleSSHCredentials-0" 
                                        wire:model="toggleSSHCredentials" 
                                        id="toggle-ssh-credentials" 
                                        name="toggle-ssh-credentials" 
                                        class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                    >
                                        <option value="No">No</option>
                                        <option value="Yes">Yes</option>
                                    </select>
                                </div>
                                <div class="sm:col-span-1 mt--4">
                                @if($toggleSMBCredentials == "No") 
                                    <dt class="text-sm font-medium text-gray-500">
                                        Windows Credential
                                    </dt>
                                    <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                        <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                        </svg>
                                        <dd class="text-sm text-gray-900">No credentials configured</dd>
                                    </div>
                                @elseif($toggleSMBCredentials == "Yes") 
                                    <dt class="text-sm font-medium text-gray-500">
                                        Windows Credential
                                    </dt>
                                    <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                        @if(!$errors->first('smbLogin') && 
                                            !$errors->first('smbPassword') &&
                                            !empty($smbLogin) &&
                                            !empty($smbPassword)) 
                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                            </svg>
                                        @else 
                                            <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                            </svg>
                                        @endif
                                        <dd class="text-sm text-gray-900">
                                            @if(!$errors->first('smbLogin') && 
                                                !$errors->first('smbPassword') &&
                                                !empty($smbLogin) &&
                                                !empty($smbPassword))
                                                {{ 'Credentials provided' }} 
                                            @else 
                                                {{ 'Please enter the credentials' }} 
                                            @endif
                                        </dd>
                                    </div>
                                @endif
                                </div>
                                <div class="sm:col-span-1">
                                    <select 
                                        wire:key="toggleSMBCredentials-0" 
                                        wire:model="toggleSMBCredentials" 
                                        id="toggle-smb-credential" 
                                        name="toggle-smb-credential" 
                                        class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                    >
                                        <option value="No">No</option>
                                        <option value="Yes">Yes</option>
                                    </select>
                                </div>
                            </dl>
                        </div>

                        @if($toggleSSHCredentials === 'Yes')
                            <div class="py-5 mb-4 bg-white border-b border-gray-200">
                                <h3 class="text-lg font-medium leading-6 text-gray-900">
                                    SSH Credentials
                                </h3>
                            </div>

                            <dl class="grid grid-cols-1 py-2 gap-x-4 gap-y-8 sm:grid-cols-2">
                                <div class="sm:col-span-1">
                                    <dt class="mt-4 text-sm font-medium text-gray-500">
                                        Authentication Method
                                    </dt>
                                </div>
                                <div class="sm:col-span-1">
                                    <select 
                                        wire:key="credentialType-0" 
                                        wire:model="credentialType" 
                                        id="credential-type" 
                                        name="credential-type" 
                                        class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                    >
                                        <option value="up">Username + Password</option>
                                        <option value="usk">Username + SSH Key</option>
                                    </select>
                                </div>
                            </dl>

                            <dl class="grid grid-cols-1 py-2 gap-x-4 gap-y-8 sm:grid-cols-2">
                                <div class="sm:col-span-1">
                                    <dt class="mt-4 text-sm font-medium text-gray-500">
                                        Preferred SSH Port
                                    </dt>
                                </div>
                                <div class="sm:col-span-1">
                                    <input 
                                        wire:key="sshPort-0" 
                                        type="text" 
                                        wire:model.lazy="sshPort" 
                                        name="ssh-port" 
                                        id="ssh-port" 
                                        class="block border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                        aria-describedby="ssh-port"
                                    >
                                    @if($errors->first('sshPort'))
                                        <div class="flex flex-row py-1 space-x-1">
                                            <div class="flex-shrink-0">
                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                </svg>
                                                </div>
                                            <p class="text-sm text-red-500">
                                                {{ $errors->first('sshPort') }}
                                            </p>
                                        </div>
                                    @endif
                                </div>
                            </dl>

                            @if($credentialType === "up")
                                <div class="flex flex-col items-center py-4 lg:flex-row">
                                    <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                        <div class="flex justify-between py-1">
                                            <label wire:key="sshLoginUP-label-0" for="location" class="block text-sm font-medium text-gray-700">Username</label>
                                            <span wire:key="sshLoginUP-span-0" class="items-end text-sm text-gray-500" id="email-optional">Required</span>
                                        </div>
                                        <div class="relative">
                                            <input 
                                                wire:key="sshLoginUP-0" 
                                                type="text" 
                                                wire:model.lazy="sshLogin" 
                                                name="ssh-login" 
                                                id="ssh-login" 
                                                placeholder="Please enter a username" 
                                                class="block @if($errors->has('sshLogin')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                aria-describedby="ssh-login"
                                            >
                                            @if($errors->first('sshLogin'))
                                                <div class="flex flex-row py-1 space-x-1">
                                                    <div class="flex-shrink-0">
                                                        <!-- Heroicon name: solid/x-circle -->
                                                        <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                        </svg>
                                                        </div>
                                                    <p class="text-sm text-red-500">
                                                        {{ $errors->first('sshLogin') }}
                                                    </p>
                                                </div>
                                            @endif
                                        </div>
                                    </div>
                                    <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                        <div class="flex justify-between py-1">
                                            <label for="location" class="block text-sm font-medium text-gray-700">Password</label>
                                            <span class="items-end text-sm text-gray-500" id="email-optional">Required</span>
                                        </div>
                                        <div class="relative">
                                            <input 
                                                wire:key="sshPasswordUP-0" 
                                                type="password" 
                                                wire:model.lazy="sshPassword" 
                                                name="ssh-password" 
                                                placeholder="Please enter a password" 
                                                id="ssh-password" 
                                                class="block @if($errors->has('sshPassword')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                aria-describedby="ssh-password"
                                            >
                                            @if($errors->first('sshPassword'))
                                                <div class="flex flex-row py-1 space-x-1">
                                                    <div class="flex-shrink-0">
                                                        <!-- Heroicon name: solid/x-circle -->
                                                        <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                        </svg>
                                                        </div>
                                                    <p class="text-sm text-red-500">
                                                        {{ $errors->first('sshPassword') }}
                                                    </p>
                                                </div>
                                            @endif
                                        </div>
                                    </div>
                                </div>
                            @elseif($credentialType === "usk")
                                <div class="flex flex-col items-center py-4 lg:flex-row">
                                    <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                        <div class="flex justify-between py-1">
                                            <label for="location" class="block text-sm font-medium text-gray-700">Username</label>
                                            <span class="items-end text-sm text-gray-500" id="ssh-username">Required</span>
                                        </div>
                                        <div class="relative">
                                            <input 
                                                wire:key="sshLoginUSK-0" 
                                                type="text" 
                                                wire:model.lazy="sshLogin" 
                                                name="ssh-username" 
                                                id="ssh-username" 
                                                placeholder="Enter username" 
                                                class="block @if($errors->has('sshLogin')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                aria-describedby="ssh-username"
                                            >
                                            @if($errors->first('sshLogin'))
                                                <div class="flex flex-row py-1 space-x-1">
                                                    <div class="flex-shrink-0">
                                                        <!-- Heroicon name: solid/x-circle -->
                                                        <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                        </svg>
                                                        </div>
                                                    <p class="text-sm text-red-500">
                                                        {{ $errors->first('sshLogin') }}
                                                    </p>
                                                </div>
                                            @endif
                                        </div>
                                    </div>
                                    <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                        <div class="flex justify-between py-1">
                                            <label for="location" class="block text-sm font-medium text-gray-700">Passphrase</label>
                                            <span class="items-end text-sm text-gray-500" id="ssh-passphrase">Required</span> 
                                        </div>
                                        <div class="relative">
                                            <input 
                                                wire:key="sshPhrase-0" 
                                                type="password" 
                                                wire:model.lazy="sshPhrase" 
                                                name="passphrase" 
                                                placeholder="Enter passphrase" 
                                                id="passphrase" 
                                                class="block @if($errors->has('sshPhrase')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                aria-describedby="passphrase"
                                            >
                                            @if($errors->first('sshPhrase'))
                                                <div class="flex flex-row py-1 space-x-1">
                                                    <div class="flex-shrink-0">
                                                        <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                        </svg>
                                                        </div>
                                                    <p class="text-sm text-red-500">
                                                        {{ $errors->first('sshPhrase') }}
                                                    </p>
                                                </div>
                                            @endif
                                        </div>
                                    </div>
                                </div>
                                    <div>
                                        <style>
                                            textarea {
                                                font-family:monospace;
                                            }
                                        </style>
                                        <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                            <div class="flex justify-between py-1">
                                                <label wire:key="sshKey-label-0" for="sshKey" class="block text-sm font-medium text-gray-700">Key</label>
                                                <span wire:key="sshKey-span-0" class="items-end text-sm text-gray-500" id="ssh-key">Required</span> 
                                            </div>
                                            <div class="mt-1">
                                                <textarea 
                                                    wire:key="sshKey-0" 
                                                    wire:model.lazy="sshKey" 
                                                    placeholder="Only PKCS1 format generated with: ssh-keygen -t ecdsa -m pem" 
                                                    rows="8" 
                                                    name="sshKey" 
                                                    id="sshKey" 
                                                    class="block w-full @if($errors->has('sshKey')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                                </textarea>
                                            @if($errors->first('sshKey'))
                                                <div class="flex flex-row py-1 space-x-1">
                                                    <div class="flex-shrink-0">
                                                        <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                        </svg>
                                                    </div>
                                                    <p class="text-sm text-red-500">
                                                        {{ $errors->first('sshKey') }}
                                                    </p>
                                                </div>
                                            @endif
                                        </div>
                                    </div>
                                </div>
                            @endif
                        @endif

                        @if($toggleSMBCredentials === 'Yes')
                            <div class="py-5 mb-4 bg-white border-b border-gray-200">
                                <h3 class="text-lg font-medium leading-6 text-gray-900">
                                    SMB Credentials
                                </h3>
                            </div>

                            <div class="flex flex-col items-center py-4 lg:flex-row">
                                <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                    <div class="flex justify-between py-1">
                                        <label for="location" class="block text-sm font-medium text-gray-700">Username</label>
                                        <span class="items-end text-sm text-gray-500" id="smb-user">Required</span>
                                    </div>
                                    <div class="relative">
                                        <input 
                                            wire:key="smbLogin-0" 
                                            type="text" 
                                            wire:model.lazy="smbLogin" 
                                            name="smb-login" 
                                            id="smb-login" 
                                            placeholder="Enter a username" 
                                            class="block @if($errors->has('smbLogin')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                            aria-describedby="smb-login"
                                        >
                                        @if($errors->first('smbLogin'))
                                            <div class="flex flex-row py-1 space-x-1">
                                                <div class="flex-shrink-0">
                                                    <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                    </svg>
                                                </div>
                                                <p class="text-sm text-red-500">
                                                    {{ $errors->first('smbLogin') }}
                                                </p>
                                            </div>
                                        @endif
                                    </div>
                                </div>
                                <!-- Code block ends -->
                                <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                    <div class="flex justify-between py-1">
                                        <label for="location" class="block text-sm font-medium text-gray-700">Password</label>
                                        <span class="items-end text-sm text-gray-500" id="smb-password">Required</span>
                                    </div>
                                    <div class="relative">
                                        <input 
                                            wire:key="smbPassword-0" 
                                            type="password" 
                                            wire:model.lazy="smbPassword" 
                                            name="name" 
                                            id="name" 
                                            placeholder="Please enter a password" 
                                            class="block @if($errors->has('smbPassword')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                            aria-describedby="scan-name"
                                        >
                                        @if($errors->first('smbPassword'))
                                            <div class="flex flex-row py-1 space-x-1">
                                                <div class="flex-shrink-0">
                                                    <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                    </svg>
                                                </div>
                                                <p class="text-sm text-red-500">
                                                    {{ $errors->first('smbPassword') }}
                                                </p>
                                            </div>
                                        @endif
                                    </div>
                                </div>
                            </div>
                        @endif

                        {{-- Page 3 Ends --}}

                        @elseif($currentPage === 4)

                        {{-- Page 4 Starts --}}

                        @if($plan === 'Free')
                        <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
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
                                        Subscribe to unlock schedules.
                                    </a>
                                </p>
                            </div>
                            </div>
                        </div>
                        @endif
                        
                        <dl class="grid grid-cols-1 py-4 gap-x-4 gap-y-8 sm:grid-cols-2">
                            <div class="sm:col-span-1">
                                @if($toggleSchedule == "Yes" && 
                                    !is_null($scheduleStartDate) && 
                                    !is_null($scheduleFrequency) &&
                                    !empty($scheduleFrequency))
                                    <dt class="text-sm font-medium text-gray-500">
                                        Schedule
                                    </dt>
                                    <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                        <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                        </svg>
                                        <dd class="text-sm text-gray-900">Schedule configured</dd>
                                    </div>
                                @else
                                    <dt class="text-sm font-medium text-gray-500">
                                        Schedule
                                    </dt>
                                    <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                        <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                        </svg>
                                        <dd class="text-sm text-gray-900">Please configure the schedule</dd>
                                    </div>
                                @endif
                            </div>
                            <div class="sm:col-span-1">
                                <select @if($plan === 'Free') {{ 'disabled'}} @endif  wire:key="toggleSchedule-0" wire:model="toggleSchedule" id="toggleSchedule" name="toggleSchedule" class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                    <option value="No">No</option>
                                    <option value="Yes">Yes</option>
                                </select>
                            </div>
                        </dl>

                        @if($toggleSchedule === 'Yes')
                        
                        <dl class="grid grid-cols-1 py-4 gap-x-4 gap-y-8 sm:grid-cols-2">
                            <div class="sm:col-span-1">
                                <dt class="text-sm font-medium text-gray-500">
                                    Start
                                </dt>
                                <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                    <dd class="text-sm text-gray-900">UTC Timezone</dd>
                                </div>
                            </div>
                            <div class="sm:col-span-1">
                                <div class="relative">
                                    <x-input.datetime-picker 
                                        wire:key="scheduleStartDate-0" 
                                        wire:model.lazy="scheduleStartDate" 
                                        class="w-full border-gray-300 rounded-md shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50" 
                                    />
                                    @if($errors->first('scheduleStartDate'))
                                        <div class="flex flex-row py-1 space-x-1">
                                            <div class="flex-shrink-0">
                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                </svg>
                                            </div>
                                            <p class="text-sm text-red-500">
                                                {{ $errors->first('scheduleStartDate') }}
                                            </p>
                                        </div>
                                    @endif
                                </div>
                            </div>
                        </dl>
                        
                        <dl class="grid grid-cols-1 py-4 gap-x-4 gap-y-8 sm:grid-cols-2">
                            <div class="sm:col-span-1">
                                <dt class="text-sm font-medium text-gray-500">
                                    Frequency
                                </dt>
                                <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                    <dd class="text-sm text-gray-900">The frequency at which a schedule has to be repeated</dd>
                                </div>
                            </div>
                            <div class="sm:col-span-1">
                                <div class="relative">
                                    <select 
                                        wire:key="scheduleFrequency-0" 
                                        wire:model="scheduleFrequency" 
                                        id="schedule-frequency" 
                                        name="schedule-frequency" 
                                        class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md js-example-basic-single w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                    >
                                        <option selected value="">Select Frequency</option>
                                        <option value="ONCE">Once</option>
                                        <option value="HOURLY">Hourly</option>
                                        <option value="DAILY">Daily</option>
                                        <option value="WEEKLY">Weekly</option>
                                        <option value="WORKWEEK">WorkWeek</option>
                                        <option value="MONTHLY">Monthly</option>
                                        {{-- <option value="CUSTOM">Custom</option> --}}
                                    </select>
                                    @if($errors->first('scheduleFrequency'))
                                        <div class="flex flex-row py-1 space-x-1">
                                            <div class="flex-shrink-0">
                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                </svg>
                                            </div>
                                            <p class="text-sm text-red-500">
                                                {{ $errors->first('scheduleFrequency') }}
                                            </p>
                                        </div>
                                    @endif
                                </div>
                            </div>
                        </dl>
                        
                            @if($scheduleFrequency === 'CUSTOM')
                            <dl class="grid grid-cols-1 py-4 gap-x-4 gap-y-8 sm:grid-cols-2">
                                <div class="sm:col-span-1">
                                    <dt class="mt-4 text-sm font-medium text-gray-500">
                                        Recurrence
                                    </dt>
                                </div>
                                <div class="sm:col-span-1">
                                    <div class="relative">
                                        <select 
                                            wire:key="scheduleRecurrence-0" 
                                            wire:model="scheduleRecurrence" 
                                            id="schedule-Recurrence" 
                                            name="schedule-Recurrence" 
                                            class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md js-example-basic-single w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                        >
                                            <option selected value="">Select Recurrence</option>
                                            <option value="ONCE">Once</option>
                                            <option value="HOURLY">Hourly</option>
                                            <option value="DAILY">Daily</option>
                                            <option value="WEEKLY">Weekly</option>
                                            <option value="MONTHLY">Monthly</option>
                                        </select>
                                    </div>
                                </div>
                            </dl>
                            @endif
                        @endif

                        {{-- Page 4 Ends --}}
                        @elseif($currentPage === 5)
                        
                        @if($plan === 'Free')
                        <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
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
                                        Subscribe to unlock email notifications.
                                    </a>
                                </p>
                            </div>
                            </div>
                        </div>
                        @endif

                        <div class="mt-1 overflow-hidden bg-white sm:rounded-lg">
                            <div class="py-5">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-1">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Email Notifications
                                        </dt>
                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                            <dd class="text-sm text-gray-900">Send email notifications</dd>
                                        </div>
                                    </div>
                                    <div class="sm:col-span-1">
                                        <select 
                                            @if($plan === 'Free') {{ 'disabled'}} @endif
                                            wire:key="emailNotification-01" 
                                            wire:model="emailNotification" 
                                            id="emailNotification" 
                                            name="emailNotification" 
                                            class="block py-2 pl-3 pr-10 mt-1 text-base @if($errors->has('emailNotification')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                        >
                                            <option value="" selected>Select Option</option>
                                            <option value="Yes">Yes</option>
                                            <option value="No">No</option>
                                        </select>
                                    </div>
                                </dl>
                            </div>
                        </div>
                        
                        @if($emailNotification === 'Yes')
                            <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                <div class="sm:col-span-1">
                                    <dt class="mt-4 text-sm font-medium text-gray-500">
                                        To:
                                    </dt>
                                    <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                        <dd class="text-sm text-gray-900">Add just one email address</dd>
                                    </div>
                                </div>
                                <div class="sm:col-span-1">
                                    <div class="flex flex-col items-start py-4">
                                        <div class="flex flex-col py-0 lg:mr-3 lg:py-0">
                                            <div class="sm:col-span-1">
                                                <input 
                                                    wire:key="emailTo-0" 
                                                    type="text" 
                                                    wire:model.lazy="emailTo" 
                                                    name="to-email" 
                                                    id="to-email" 
                                                    placeholder="" 
                                                    class="block @if($errors->has('emailTo')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                    aria-describedby="to-email"
                                                >
                                            </div>
                                            @if($errors->first('emailTo'))
                                                <div class="flex flex-row py-1 space-x-1">
                                                    <div class="flex-shrink-0">
                                                        <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                        </svg>
                                                    </div>
                                                    <p class="text-sm text-red-500">
                                                        {{ $errors->first('emailTo') }}
                                                    </p>
                                                </div>
                                            @endif
                                        </div>
                                    </div>
                                </div>
                            </dl>
                        @endif

                        @elseif($currentPage === 6)

                        {{-- Page 5 Starts --}}
                                            
                        <div class="py-4">
                            <div>
                                <h3 class="text-lg font-medium leading-6 text-gray-900">
                                    Scan Information
                                </h3>
                                <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                    Scan details and configuration
                                </p>
                            </div>
                            <div class="mt-5 border-t border-gray-200">
                                <dl class="sm:divide-y sm:divide-gray-200">
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Name
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            {{ $scanName }}
                                        </dd>
                                    </div>
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Description
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            {{ $scanDescription }}
                                        </dd>
                                    </div>
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Targets Included
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            {{ $targetList }}
                                        </dd>
                                    </div>
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Targets Excluded
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            @if($toggleExcludeTargets === 'No')
                                                {{ 'No targets excluded from the assets in scope' }}
                                            @else
                                                {{ $targetExclude }}
                                            @endif
                                        </dd>
                                    </div>
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Port Scanning
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            @if($targetPorts === 'fd591a34-56fd-11e1-9f27-406186ea4fc5')
                                                {{ 'All TCP Ports from 1 to 65535' }}
                                            @elseif($targetPorts === 'ab33f6b0-57f8-11e1-96f5-406186ea4fc5')
                                                {{ 'Top TCP and UDP Ports' }}
                                            @elseif($targetPorts === '730ef368-57e2-11e1-a90f-406186ea4fc5')
                                                {{ 'All TCP Ports from 1 to 65535 and Top UDP ports' }}
                                            @elseif($targetPorts === 'customports')
                                                {{ $portRange }}
                                            @endif
                                        </dd>
                                    </div>
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Host Discovery
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            @if($targetAlive === '2')
                                                {{ 'ARP Ping' }}
                                            @elseif($targetAlive === '1')
                                                {{ 'ICMP Ping' }}
                                            @elseif($targetAlive === '6')
                                                {{ 'TCP-ACK Ping' }}
                                            @elseif($targetAlive === '7')
                                                {{ 'TCP-SYN Ping' }}
                                            @elseif($targetAlive === '5')
                                                {{ 'Consider Alive' }}
                                            @elseif($targetAlive === '8')
                                                {{ 'ICMP and ARP Ping' }}
                                            @elseif($targetAlive === '9')
                                                {{ 'TCP-ACK and ARP Ping' }}
                                            @elseif($targetAlive === '16')
                                                {{ 'TCP-SYN Service Ping' }}
                                            @elseif($targetAlive === '4')
                                                {{ 'ICMP and TCP-ACK Ping' }}
                                            @elseif($targetAlive === '3')
                                                {{ 'ICMP, TCP-ACK and ARP Ping' }}
                                            @endif
                                        </dd>
                                    </div>
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Speed
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            @if($scanSpeed === '1')
                                                {{ 'Good for slow networks' }}
                                            @elseif($scanSpeed === '3')
                                                {{ 'Good for fast networks' }}
                                            @elseif($scanSpeed === '2')
                                                {{ 'Good for normal networks' }}
                                            @endif
                                        </dd>
                                    </div>
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Credentials
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            @if($toggleSSHCredentials === 'Yes')
                                                <span class="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-50 text-green-800">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 mr-1 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                                                    </svg>
                                                    SSH Credentials
                                                </span>
                                            @endif
                                            @if($toggleSMBCredentials === 'Yes')
                                                <span class="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-50 text-green-800">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 mr-1 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                                                    </svg>
                                                    SMB Credentials
                                                </span>
                                            @endif
                                            @if($toggleSMBCredentials === 'No' && $toggleSSHCredentials === 'No')
                                                Unauthenticated Scan
                                            @endif
                                        </dd>
                                    </div>
                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                        <dt class="text-sm font-medium text-gray-500">
                                            Schedule
                                        </dt>
                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                            @if($toggleSchedule === 'Yes')
                                                <ul>
                                                    <li>Timezone: {{ $timezone }}</li>
                                                    <li>Frequency: 
                                                        @if($scheduleFrequency === 'WEEKLY')
                                                            {{ 'Weekly' }}
                                                        @elseif($scheduleFrequency === 'DAILY')
                                                            {{ 'Daily' }}
                                                        @elseif($scheduleFrequency === 'ONCE')
                                                            {{ 'Once' }}
                                                        @elseif($scheduleFrequency === 'MONTHLY')
                                                            {{ 'Monthly' }}
                                                        @elseif($scheduleFrequency === 'WORKWEEK')
                                                            {{ 'Workweek' }}
                                                        @elseif($scheduleFrequency === 'HOURLY')
                                                            {{ 'Hourly' }}
                                                        @endif
                                                    </li>
                                                    <li>Starts: {{ $scheduleStartDate }}</li>
                                                </ul>
                                            @else
                                                {{ 'Unscheduled' }}
                                            @endif
                                        </dd>
                                    </div>
                                    @if(!empty($emailTo))
                                        <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                            <dt class="text-sm font-medium text-gray-500">
                                                Notification
                                            </dt>
                                            <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                {{ $emailTo }}
                                            </dd>
                                        </div>
                                    @endif
                                </dl>
                            </div>
                        </div>
                        
                        {{-- Page 5 Ends --}}
                            
                        @endif
                    </x-slot>

                    <x-slot name="footer">
                        <div class="flex items-center justify-between">
                            @if($currentPage === 1)
                                <x-jet-secondary-button wire:click="closeShowModal">
                                    Cancel
                                </x-jet-secondary-button>
                            @elseif($currentPage <= 6)
                                <x-jet-secondary-button wire:click="backPage">
                                    Back
                                </x-jet-secondary-button>
                            @endif

                            @if($currentPage === 1)
                                <x-jet-button class="ml-2" wire:click="firstStepSubmit">
                                    Next
                                </x-jet-button>
                            @elseif($currentPage === 2)
                                <x-jet-button class="ml-2" wire:click="secondStepSubmit">
                                    Next
                                </x-jet-button>
                            @elseif($currentPage === 3)
                                <x-jet-button class="ml-2" wire:click="thirdStepSubmit">
                                    Next
                                </x-jet-button>
                            @elseif($currentPage === 4)
                                <x-jet-button class="ml-2" wire:click="fourthStepSubmit">
                                    Next
                                </x-jet-button>
                            @elseif($currentPage === 5)
                                <x-jet-button class="ml-2" wire:click="fifthStepSubmit">
                                    Next
                                </x-jet-button>
                            @elseif($currentPage === 6)
                                @if(env('APP_ENV') === 'demo')
                                    <x-jet-button class="ml-2 cursor-not-allowed" wire:click="saveCreateScan" disabled>
                                        Save
                                    </x-jet-button>
                                @else
                                    <x-jet-button class="ml-2" wire:click="saveCreateScan">
                                        Save
                                    </x-jet-button>
                                @endif
                            @endif
                        </div>
                    </x-slot>
                </x-jet-dialog-modal>

                @if($scans->count())
                    {{-- Modal Delete Scan --}}
                    <x-modal.dialog wire:model.defer="deleteModalFormVisible" maxWidth="mds">
                        <x-slot name="title">
                            Delete Scan
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
                                            Are you sure you want to delete this scan? Once the scan is deleted, all of its resources, results, reports, assets and data will be permanently deleted.
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </x-slot>

                        <x-slot name="footer">
                            <x-jet-secondary-button wire:click="closeDeleteShowModal" >
                                {{ __('Cancel') }}
                            </x-jet-secondary-button>

                            <x-jet-danger-button class="ml-2" wire:click="taskDelete('{{ $taskID }}')">
                                Delete
                            </x-jet-danger-button>
                        </x-slot>
                    </x-modal.dialog>

                    {{-- Modal Delete Scan Confirmation --}}
                    <x-jet-dialog-modal wire:model.defer="deleteModalConfirmationFormVisible" maxWidth="mds">
                        <x-slot name="title">
                            Scan Deleted Successfully
                        </x-slot>

                        <x-slot name="content">
                            {{ __('The scan was deleted successfully') }}
                        </x-slot>

                        <x-slot name="footer">
                            <x-jet-secondary-button wire:click="closeDeleteModalConfirmationForm" >
                                {{ __('Close') }}
                            </x-jet-secondary-button>
                        </x-slot>
                    </x-jet-dialog-modal>

                    {{-- Modal Delete Scan Confirmation --}}
                    <form wire:submit.prevent="deleteSelected">
                        <x-modal.dialog wire:model.defer="showDeleteModal" maxWidth="mds">
                            <x-slot name="title">
                                Delete Scans
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
                                                Are you sure you want to delete these scans? This action is irreversible. Once they are deleted, all of their resources, results, reports, assets and data will be permanently deleted.
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </x-slot>

                            <x-slot name="footer">
                                <x-jet-secondary-button wire:click="$set('showDeleteModal', false)" >
                                    Cancel
                                </x-jet-secondary-button>

                                <x-jet-danger-button class="ml-2" type="submit">
                                    Delete
                                </x-jet-danger-button>
                            </x-slot>
                        </x-modal.dialog>
                    </form>

                    {{-- Modal Edit Scan --}}
                    <div>
                        <x-modal.dialog wire:model="showEditModal" maxWidth="mds" wire:key="editModal-0">
                            <x-slot name="title">
                                <div class="flex items-center justify-between">
                                    <div>
                                        Edit {{ $pages[$currentPage]['heading'] }} of Scan {{ $scanName }}
                                        <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                            {{ $pages[$currentPage]['subheading'] }}
                                        </p>
                                    </div>
                                    <div 
                                        x-data
                                        x-tooltip="Close"
                                        wire:click="closeEditModal" 
                                        wire:key="closeCreateScanModalButton-0">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-gray-500 cursor-pointer hover:text-gray-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </div>
                                </div>
                            </x-slot>
    
                            <x-slot name="content">
                                <nav aria-label="Progress">
                                    <ol role="list" class="pt-2 pb-2 space-y-4 md:flex md:space-y-0 md:space-x-8">
                                        <li class="md:flex-1">
                                            <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage === 1){{'blue-400 animate-pulse'}}@elseif($currentPage >= 2){{'blue-700'}}@endif hover:border-indigo-800 md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                                <span class="text-xs font-semibold tracking-wide text-indigo-600 uppercase group-hover:text-indigo-800">Step 1</span>
                                                <span class="text-sm font-medium">Template</span>
                                            </a>
                                        </li>
        
                                        <li class="md:flex-1">
                                            <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage < 2){{'gray-200'}}@elseif($currentPage === 2){{'blue-400 animate-pulse'}}@elseif($currentPage >= 2){{'blue-700'}}@endif hover:border-gray-300 md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                                <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 2</span>
                                                <span class="text-sm font-medium">Targets</span>
                                            </a>
                                        </li>
        
                                        <li class="md:flex-1">
                                            <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage <= 2){{'gray-200'}}@elseif($currentPage === 3){{'indigo-400 animate-pulse'}}@elseif($currentPage >= 4){{'indigo-700'}}@endif  hover:border-gray-300 md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                                <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 3</span>
                                                <span class="text-sm font-medium">Credentials</span>
                                            </a>
                                        </li>
        
                                        <li class="md:flex-1">
                                            <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage <= 3){{'gray-200'}}@elseif($currentPage === 4){{'blue-400 animate-pulse'}}@elseif($currentPage >= 5){{'blue-700'}}@endif hover:border-blue-400 hover:animate-pulse md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                                <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 4</span>
                                                <span class="text-sm font-medium">Schedules</span>
                                            </a>
                                        </li>
                                        
                                        <li class="md:flex-1">
                                            <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage <= 4){{'gray-200'}}@elseif($currentPage === 5){{'blue-400 animate-pulse'}}@elseif($currentPage === 6){{'blue-700'}}@endif hover:border-blue-400 hover:animate-pulse md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                                <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 5</span>
                                                <span class="text-sm font-medium">Notifications</span>
                                            </a>
                                        </li>
        
                                        <li class="md:flex-1">
                                            <a href="#" class="group pl-4 py-2 flex flex-col border-l-4 border-@if($currentPage <= 5){{'gray-200'}}@elseif($currentPage === 6){{'blue-400 animate-pulse'}}@endif hover:border-gray-300 md:pl-0 md:pt-4 md:pb-0 md:border-l-0 md:border-t-4">
                                                <span class="text-xs font-semibold tracking-wide text-gray-500 uppercase group-hover:text-gray-700">Step 6</span>
                                                <span class="text-sm font-medium">Review</span>
                                            </a>
                                        </li>
                                    </ol>
                                </nav>
    
                                @if($currentPage === 1)
                                    <div class="px-4 py-5 border-t border-gray-200 sm:p-0">
                                        <dl class="sm:divide-y sm:divide-gray-200">
                                            <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                <dt class="mt-3 text-sm font-medium text-gray-500 sm:mt-3">
                                                    Name
                                                </dt>
                                                <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                    <input 
                                                        wire:key="scanName-Edit-0" 
                                                        type="text" 
                                                        wire:model.lazy="scanName" 
                                                        name="name" 
                                                        id="name" 
                                                        class="shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm @if($errors->has('scanName')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md" 
                                                        placeholder="@if($errors->has('scanName')){{'Required'}}@else{{'Scan name'}}@endif" 
                                                        aria-describedby="scan-name"
                                                    >
                                                    @if($errors->first('scanName'))
                                                        <p class="mt-1 text-sm text-red-500">{{ $errors->first('scanName') }}</p>
                                                    @elseif($scanName != "")
                                                        <div class="flex flex-row mt-2 space-x-1">
                                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                            </svg>
                                                            <p class="text-sm text-gray-500">Configured</p>
                                                        </div>
                                                    @else 
                                                        <p class="mt-1 text-sm text-gray-500">Required</p>
                                                    @endif
                                                </dd>
                                            </div>
                                            <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                <dt class="mt-8 text-sm font-medium text-gray-500">
                                                    Description
                                                </dt>
                                                <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                    <textarea 
                                                        wire:key="scanDescription-12" 
                                                        wire:model.lazy="scanDescription" 
                                                        id="targetList" 
                                                        name="targetList" 
                                                        rows="3" 
                                                        class="block max-w-xl border @if($errors->has('scanDescription')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm w-full focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" 
                                                        placeholder="@if($errors->has('scanDescription')){{'Required'}}@else{{'Description'}}@endif">
                                                    </textarea>
                                                    @if($errors->first('scanDescription'))
                                                        <p class="mt-1 text-sm text-red-500">{{ $errors->first('scanDescription') }}</p>
                                                    @elseif($scanDescription != "")
                                                        <div class="flex flex-row mt-2 space-x-1">
                                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                            </svg>
                                                            <p class="text-sm text-gray-500">Configured</p>
                                                        </div>
                                                    @else 
                                                        <p class="mt-1 text-sm text-gray-500">Required</p>
                                                    @endif
                                                </dd>
                                            </div>
                                        </dl>
                                    </div>
                                @elseif($currentPage === 2)
                                    <div class="py-5">
                                        <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                            
                                            <div class="sm:col-span-1">
                                                {{-- Handle Messages --}}
                                                @if(!$errors->first('targetList') && $targetList != "") 
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Include Targets
                                                    </dt>
                                                    <div class="flex flex-row flex-shrink-0 mt-2 space-x-2">
                                                        <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                        </svg>
                                                        <dd class="text-sm text-gray-900">Assets configured</dd>
                                                    </div>
                                                @elseif($errors->first('targetList')) 
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Exclude Targets
                                                    </dt>
                                                    <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                        <svg class="w-5 h-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                                                            </svg>
                                                        <dd class="text-sm text-gray-900">Errors in assets</dd>
                                                    </div>
                                                @else
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Include Targets
                                                    </dt>
                                                    <div class="flex flex-row flex-shrink-0 mt-2 space-x-2">
                                                        <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                        </svg>
                                                        <dd class="text-sm text-gray-900">No assets configured</dd>
                                                    </div>
                                                @endif
                                            </div>
                                            <div class="sm:col-span-1">
                                                <textarea 
                                                    wire:key="targetList-edit" 
                                                    wire:model.lazy="targetList" 
                                                    id="targetList" 
                                                    name="targetList" 
                                                    rows="3" 
                                                    class="block max-w-xl border border-gray-300 rounded-md shadow-sm w-80 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                                </textarea>
                                                {{-- Handle Errors --}}
                                                @if($errors->first('targetList'))
                                                    <div class="flex flex-row py-1 space-x-1">
                                                        <div class="flex-shrink-0">
                                                            <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                            </svg>
                                                        </div>
                                                        <p class="text-sm text-red-500">
                                                            {{ $errors->first('targetList') }}
                                                        </p>
                                                    </div>
                                                @endif
                                            </div>
                                            <div class="sm:col-span-1">
                                                <dt class="mt-4 text-sm font-medium text-gray-500">
                                                    Do you want to exclude targets?
                                                </dt>
                                            </div>
                                            <div class="sm:col-span-1">
                                                <select 
                                                    wire:key="toggleExcludeTargets-edit" 
                                                    wire:model="toggleExcludeTargets" 
                                                    id="toggle-exclude-targets" 
                                                    name="toggle-exclude-targets" 
                                                    class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                >
                                                    <option value="No">No</option>
                                                    <option value="Yes">Yes</option>
                                                </select>
                                            </div>
                                            @if($toggleExcludeTargets === 'Yes')
                                                <div class="sm:col-span-1">
                                                    @if(!$errors->first('targetExclude') && $targetExclude != $targetList && $targetExclude != '') 
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            Exclude Targets
                                                        </dt>
                                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                            </svg>
                                                            <dd class="text-sm text-gray-900">Exclusion configured</dd>
                                                        </div>
                                                    @elseif($errors->first('targetExclude')) 
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            Exclude Targets
                                                        </dt>
                                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                            <svg class="w-5 h-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                                                                </svg>
                                                            <dd class="text-sm text-gray-900">Errors in exclusions</dd>
                                                        </div>
                                                    @else
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            Exclude Targets
                                                        </dt>
                                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                            <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                            </svg>
                                                            <dd class="text-sm text-gray-900">No exclusion configured</dd>
                                                        </div>
                                                    @endif
                                                </div>
                                                <div class="sm:col-span-1">
                                                    <textarea 
                                                        wire:key="targetExclude-edit" 
                                                        wire:model.lazy="targetExclude" 
                                                        id="targetExclude" 
                                                        name="targetExclude" 
                                                        rows="3" 
                                                        class="block max-w-xl border border-gray-300 rounded-md shadow-sm w-80 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                                    </textarea>
                                                    {{-- Error from validation --}}
                                                    @if($errors->first('targetExclude'))
                                                        <div class="flex flex-row py-1 space-x-1">
                                                            <div class="flex-shrink-0">
                                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                </svg>
                                                            </div>
                                                            <p class="text-sm text-red-500">
                                                                {{ $errors->first('targetExclude') }}
                                                            </p>
                                                        </div>
                                                    @endif
                                                </div>
                                            @endif
                                        </dl>
                                    </div>
    
                                    <div class="mt-2 overflow-hidden bg-white sm:rounded-lg">
                                        <div class="py-5">
                                            <h3 class="text-lg font-medium leading-6 text-gray-900">
                                                Port Scanning
                                            </h3>
                                            <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                                A port scan is a method for determining which ports on a target are open.
                                            </p>
                                        </div>
                                        <div class="py-5">
                                            <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                                <div class="sm:col-span-1">
                                                    @if($targetPorts != "customports" || $portRange != "") 
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            Ports to Scan
                                                        </dt>
                                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                            </svg>
                                                            <dd class="text-sm text-gray-900">Ports configured</dd>
                                                        </div>
                                                    @else
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            Ports to Scan
                                                        </dt>
                                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                            <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                            </svg>
                                                            <dd class="text-sm text-gray-900">Configure custom ports</dd>
                                                        </div>
                                                    @endif
                                                </div>
                                                <div class="sm:col-span-1">
                                                    <select 
                                                        wire:key="targetPorts-edit" 
                                                        wire:model="targetPorts" 
                                                        id="target-ports" 
                                                        name="target-ports" 
                                                        class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                    >
                                                        <option value="fd591a34-56fd-11e1-9f27-406186ea4fc5">All TCP Ports from 1 to 65535</option>
                                                        <option value="ab33f6b0-57f8-11e1-96f5-406186ea4fc5">Top TCP and UDP Ports</option>
                                                        <option value="730ef368-57e2-11e1-a90f-406186ea4fc5">All TCP and Top 100 UDP Ports</option>
                                                        <option value="customports">Custom</option>
                                                    </select>
                                                </div>
                                            </dl>
                                            @if($targetPorts === 'customports')
                                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                                    <div class="sm:col-span-1">
                                                        <dt class="mt-12 text-sm font-medium text-gray-500">
                                                            Custom Ports
                                                        </dt>
                                                    </div>
                                                    <div class="sm:col-span-1">
                                                        <div class="flex flex-col items-start py-4">
                                                            <div class="flex flex-col py-4 lg:mr-3 lg:py-0">
                                                                <div class="sm:col-span-3">
                                                                    <textarea 
                                                                        wire:key="portRange-edit" 
                                                                        wire:model.lazy="portRange" 
                                                                        placeholder="T:1-5,7,9,U:1-3,5,7,9" 
                                                                        id="port-range" 
                                                                        name="port-range" 
                                                                        rows="3" 
                                                                        class="block max-w-xl border border-gray-300 rounded-md shadow-sm w-80 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                                                    </textarea>
                                                                </div>
                                                                @if($errors->first('portRange'))
                                                                    <div class="flex flex-row py-1 space-x-1">
                                                                        <div class="flex-shrink-0">
                                                                            <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                            </svg>
                                                                        </div>
                                                                        <p class="text-sm text-red-500">
                                                                            {{ $errors->first('portRange') }}
                                                                        </p>
                                                                    </div>
                                                                @endif
                                                            </div>
                                                        </div>
                                                    </div>
                                                </dl>
                                            @endif
                                        </div>
                                    </div>
    
                                    <div class="mt-2 overflow-hidden bg-white sm:rounded-lg">
                                        <div class="py-5">
                                            <h3 class="text-lg font-medium leading-6 text-gray-900">
                                                Host Discovery Method
                                            </h3>
                                            <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                                Host discovery refers to network hosts' enumeration to gather information about the hosts.
                                            </p>
                                        </div>
                                        <div class="py-5">
                                            <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                                <div class="sm:col-span-1">
                                                    @if($targetAlive != "") 
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            Host Discovery
                                                        </dt>
                                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                            </svg>
                                                            <dd class="text-sm text-gray-900">Discovery configured</dd>
                                                        </div>
                                                    @endif
                                                </div>
                                                <div class="sm:col-span-1">
                                                    <select 
                                                        wire:key="targetAlive-edit" 
                                                        wire:model="targetAlive" 
                                                        id="location" 
                                                        name="location" 
                                                        class="block py-2 pl-3 pr-10 mt-1 text-base @if($errors->has('targetAlive')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                    >
                                                        <option value="2">ICMP Ping</option>
                                                        <option value="4">ARP Ping</option>
                                                        <option value="7">ICMP, TCP-ACK Service & ARP Ping</option>
                                                        <option value="3">ICMP & TCP-ACK Service Ping</option>
                                                        <option value="8">Consider Alive</option>
                                                        <option value="1">TCP-ACK Ping</option>
                                                        <option value="16">TCP-SYN Ping</option>
                                                        <option value="6">ICMP & ARP Ping</option>
                                                        <option value="5">TCP-ACK & ARP Ping</option>
                                                    </select>
                                                </div>
                                            </dl>
                                        </div>
                                    </div>
    
                                    <div class="mt-4 overflow-hidden bg-white sm:rounded-lg">
                                        <div class="py-5">
                                            <h3 class="text-lg font-medium leading-6 text-gray-900">
                                                Performance Settings
                                            </h3>
                                            <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                                Configure scan speed and number of concurrent tests and hosts.
                                            </p>
                                        </div>
                                        <div class="py-5">
                                            <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                                <div class="sm:col-span-1">
                                                    @if($scanSpeed != "") 
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            Scan Speed
                                                        </dt>
                                                        <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                            </svg>
                                                            <dd class="text-sm text-gray-900">Speed configured</dd>
                                                        </div>
                                                    @endif
                                                </div>
                                                <div class="sm:col-span-1">
                                                    <select 
                                                        wire:key="scanSpeed-edit" 
                                                        wire:model="scanSpeed" 
                                                        id="scanSpeed" 
                                                        name="scanSpeed" 
                                                        class="block py-2 pl-3 pr-10 mt-1 text-base @if($errors->has('scanSpeed')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                    >
                                                        <option value="1">Slow</option>
                                                        <option value="2">Normal</option>
                                                        <option value="3">Fast</option>
                                                    </select>
                                                </div>
                                            </dl>
    
                                        </div>
                                    </div>
    
                                @elseif($currentPage === 3)
                                    <div class="py-5">
                                        <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                            @if($hasSSHCredentials === 'Yes') 
                                                <div class="sm:col-span-1">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        SSH Credentials
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900">
                                                        <div class="flex flex-row">
                                                            @if($credentialType == "usk")
                                                                @if($toggleSSHCredentials == 'Remove')
                                                                    <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    Removed
                                                                @elseif($toggleSSHCredentials == 'Edit')
                                                                    @if($errors->first('sshLogin') || 
                                                                        $errors->first('sshPhrase') || 
                                                                        $errors->first('sshKey') ||
                                                                        empty($sshLogin) ||
                                                                        empty($sshPhrase) ||
                                                                        empty($sshKey))
                                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        Editing
                                                                    @else
                                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        Configured
                                                                    @endif
                                                                @elseif($toggleSSHCredentials == '' || $toggleSSHCredentials == 'No')
                                                                    <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    Configured
                                                                @endif
                                                            @elseif($credentialType == "up")
                                                                @if($toggleSSHCredentials == 'Remove')
                                                                    <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    Removed
                                                                @elseif($toggleSSHCredentials == 'Edit')
                                                                    @if($errors->first('sshLogin') || 
                                                                        $errors->first('sshPassword') || 
                                                                        empty($sshLogin) ||
                                                                        empty($sshPassword))
                                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        Editing
                                                                    @else
                                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        Configured
                                                                    @endif
                                                                @elseif($toggleSSHCredentials == '' || $toggleSSHCredentials == 'No')
                                                                    <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    Configured
                                                                @endif
                                                            @endif
                                                        </div>
                                                    </dd>
                                                </div>
                                            @elseif($hasSSHCredentials === 'No')
                                                @if($credentialType == 'up')
                                                    <div class="sm:col-span-1">
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            SSH Credentials
                                                        </dt>
                                                        <dd class="mt-1 text-sm text-gray-900">
                                                            <div class="flex flex-row">
                                                                @if($toggleSSHCredentials == "No" || $toggleSSHCredentials == "")
                                                                    <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    &nbsp; No credentials provided
                                                                @endif
                                                                @if($toggleSSHCredentials == 'Create')
                                                                    @if(!$errors->first('sshLogin') && !$errors->first('sshPassword') && !empty($sshLogin) && !empty($sshPassword)) 
                                                                        <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        &nbsp; Entered
                                                                    @elseif($errors->first('sshLogin') || $errors->first('sshPassword') || empty($sshLogin) || empty($sshPassword)) 
                                                                        <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        &nbsp; Creating
                                                                    @endif
                                                                @endif
                                                            </div>
                                                        </dd>
                                                    </div>
                                                @elseif($credentialType == 'usk')
                                                    <div class="sm:col-span-1">
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            SSH Credentials
                                                        </dt>
                                                        <dd class="mt-1 text-sm text-gray-900">
                                                            <div class="flex flex-row">
                                                                @if($toggleSSHCredentials == "No" || $toggleSSHCredentials == "")
                                                                    <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    &nbsp; No credentials provided
                                                                @elseif($toggleSSHCredentials == 'Create')
                                                                    @if(!$errors->first('sshLogin') && !$errors->first('sshPhrase') && !$errors->first('sshKey') && !empty($sshLogin) && !empty($sshPhrase) && !empty($sshKey)) 
                                                                        <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        &nbsp; Entered
                                                                    @else 
                                                                        <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        &nbsp; Creating
                                                                    @endif
                                                                @endif
                                                            </div>
                                                        </dd>
                                                    </div>
                                                @endif
                                            @endif
                                            
                                            <div class="sm:col-span-1">
                                                <select 
                                                    wire:key="toggleSSHCredentials-edit" 
                                                    wire:model="toggleSSHCredentials" 
                                                    id="toggle-ssh-credentials" 
                                                    name="toggle-ssh-credentials" 
                                                    class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                >
                                                    @if($hasSSHCredentials === 'Yes') 
                                                        <option selected value="">Select an option...</option>
                                                        <option value="Edit">Edit</option>
                                                        <option value="Remove">Remove</option>
                                                    @else
                                                        <option selected value="">Select an option</option>
                                                        <option value="Create">Create</option>
                                                    @endif
                                                </select>
                                            </div>
                                            
                                            <div class="sm:col-span-1">
                                            @if($hasSMBCredentials === 'Yes') 
                                                <div class="sm:col-span-1">
                                                    <dt class="text-sm font-medium text-gray-500">Windows Credentials</dt>
                                                    <dd class="mt-1 text-sm text-gray-900">
                                                        <div class="flex flex-row">
                                                            @if($toggleSMBCredentials == 'Remove')
                                                                <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                </svg>
                                                                Removed
                                                            @elseif($toggleSMBCredentials == 'Edit')
                                                                @if($errors->first('smbLogin') || 
                                                                        $errors->first('smbPassword') || 
                                                                        empty($smbLogin) ||
                                                                        empty($smbPassword))
                                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        Editing
                                                                    @else
                                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                        </svg>
                                                                        Configured
                                                                    @endif
                                                            @elseif($toggleSMBCredentials == '' || $toggleSMBCredentials == 'No')
                                                                <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                </svg>
                                                                Configured
                                                            @endif
                                                        </div>
                                                    </dd>
                                                </div>
                                            @elseif($hasSMBCredentials === 'No')
                                                <div class="sm:col-span-1">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Windows Credentials
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900">
                                                        <div class="flex flex-row">
                                                            @if($toggleSMBCredentials == 'No' || $toggleSMBCredentials == '')
                                                                <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                                </svg>
                                                                No credentials provided
                                                            @elseif($toggleSMBCredentials == 'Create')
                                                                @if($errors->first('smbLogin') || $errors->first('smbPassword') || empty($smbLogin) || empty($smbPassword)) 
                                                                    <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    &nbsp; Creating
                                                                @elseif(!$errors->first('smbLogin') && !$errors->first('smbPassword') && !empty($smbLogin) && !empty($smbPassword)) 
                                                                    <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    &nbsp; Entered
                                                                @endif
                                                            @endif
                                                        </div>
                                                    </dd>
                                                </div>
                                            @endif
                                            </div>
                                            
                                            <div class="sm:col-span-1">
                                                <select 
                                                    wire:key="toggleSMBCredentials-edit" 
                                                    wire:model="toggleSMBCredentials" 
                                                    id="toggle-smb-credentials" 
                                                    name="toggle-smb-credentials" 
                                                    class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                >
                                                    @if($hasSMBCredentials === 'Yes') 
                                                        <option selected value="">Select an option...</option>
                                                        <option value="Edit">Edit</option>
                                                        <option value="Remove">Remove</option>
                                                    @else
                                                        <option selected value="">Select an option</option>
                                                        <option value="Create">Create</option>
                                                    @endif
                                                </select>
                                            </div>
                                            
                                        </dl>
                                    </div>
    
                                    @if($toggleSSHCredentials === 'Edit' || $toggleSSHCredentials === 'Create')
                                        <div class="py-5 mb-4 bg-white border-b border-gray-200">
                                            <h3 class="text-lg font-medium leading-6 text-gray-900">
                                                SSH Credentials
                                            </h3>
                                        </div>
    
                                        @if($hasSSHCredentials === 'No')
                                            <dl class="grid grid-cols-1 py-2 gap-x-4 gap-y-8 sm:grid-cols-2">
                                                <div class="sm:col-span-1">
                                                    <dt class="mt-4 text-sm font-medium text-gray-500">
                                                        Authentication Method
                                                    </dt>
                                                </div>
                                                <div class="sm:col-span-1">
                                                    <select 
                                                        wire:key="credentialType-edit" 
                                                        wire:model="credentialType" 
                                                        id="credential-type" 
                                                        name="credential-type" 
                                                        class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                    >
                                                        <option value="up">Username + Password</option>
                                                        <option value="usk">Username + SSH Key</option>
                                                    </select>
                                                </div>
                                            </dl>
                                        @endif
    
                                        <dl class="grid grid-cols-1 py-2 gap-x-4 gap-y-8 sm:grid-cols-2">
                                            <div class="sm:col-span-1">
                                                <dt class="mt-2 text-sm font-medium text-gray-500">
                                                    Preferred SSH Port
                                                </dt>
                                            </div>
                                            <div class="sm:col-span-1">
                                                <input 
                                                    wire:key="sshPort-edit" 
                                                    type="text" 
                                                    wire:model.lazy="sshPort" 
                                                    name="ssh-port" 
                                                    id="ssh-port" 
                                                    class="block border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" aria-describedby="scan-name"
                                                >
                                                @if($errors->first('sshPort'))
                                                    <div class="flex flex-row py-1 space-x-1">
                                                        <div class="flex-shrink-0">
                                                            <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                            </svg>
                                                            </div>
                                                        <p class="text-sm text-red-500">
                                                            {{ $errors->first('sshPort') }}
                                                        </p>
                                                    </div>
                                                @endif
                                            </div>
                                        </dl>
    
                                        @if($credentialType === "up")
                                            <div class="flex flex-col items-center py-4 lg:flex-row">
                                                <!-- Code block starts -->
                                                <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                                    <div class="flex justify-between py-1">
                                                        <label for="location" class="block text-sm font-medium text-gray-700">Username</label>
                                                        <span class="items-end text-sm text-gray-500" id="email-optional">Required</span>
                                                    </div>
                                                    <div class="relative">
                                                        <input 
                                                            wire:key="sshLogin-edit" 
                                                            type="text" 
                                                            wire:model.lazy="sshLogin" 
                                                            placeholder="@if($errors->has('sshLogin')){{'Enter username'}}@endif" name="name" id="name" class="block @if($errors->has('sshLogin')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                            aria-describedby="scan-name"
                                                        >
                                                        @if($errors->first('sshLogin'))
                                                            <div class="flex flex-row py-1 space-x-1">
                                                                <div class="flex-shrink-0">
                                                                    <!-- Heroicon name: solid/x-circle -->
                                                                    <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    </div>
                                                                <p class="text-sm text-red-500">
                                                                    {{ $errors->first('sshLogin') }}
                                                                </p>
                                                            </div>
                                                        @endif
                                                    </div>
                                                </div>
                                                <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                                    <div class="flex justify-between py-1">
                                                        <label for="location" class="block text-sm font-medium text-gray-700">Password</label>
                                                        <span class="items-end text-sm text-gray-500" id="email-optional">Required</span>
                                                    </div>
                                                    <div class="relative">
                                                        <input 
                                                            wire:key="sshPassword-edit" 
                                                            type="password" 
                                                            placeholder="@if($errors->has('sshPassword')){{'Enter password'}}@endif" 
                                                            wire:model.lazy="sshPassword" 
                                                            name="ssh-password-edit" 
                                                            id="ssh-password-edit" 
                                                            class="block @if($errors->has('sshPassword')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                            aria-describedby="scan-name"
                                                        >
                                                        @if($errors->first('sshPassword'))
                                                            <div class="flex flex-row py-1 space-x-1">
                                                                <div class="flex-shrink-0">
                                                                    <!-- Heroicon name: solid/x-circle -->
                                                                    <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    </div>
                                                                <p class="text-sm text-red-500">
                                                                    {{ $errors->first('sshPassword') }}
                                                                </p>
                                                            </div>
                                                        @endif
                                                    </div>
                                                </div>
                                            </div>
                                        @elseif($credentialType === "usk")
                                            <div class="flex flex-col items-center py-4 lg:flex-row">
                                                <!-- Code block starts -->
                                                <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                                    <div class="flex justify-between py-1">
                                                        <label for="location" class="block text-sm font-medium text-gray-700">Username</label>
                                                        <span class="items-end text-sm text-gray-500" id="ssh-username">Required</span>
                                                    </div>
                                                    <div class="relative">
                                                        <input 
                                                            wire:key="sshLogin-edit" 
                                                            type="text" 
                                                            wire:model.lazy="sshLogin" 
                                                            name="ssh-login" 
                                                            id="ssh-login" 
                                                            placeholder="@if($errors->has('sshLogin')){{'Enter username'}}@endif" class="block @if($errors->has('sshLogin')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                            aria-describedby="scan-name"
                                                        >
                                                        @if($errors->first('sshLogin'))
                                                            <div class="flex flex-row py-1 space-x-1">
                                                                <div class="flex-shrink-0">
                                                                    <!-- Heroicon name: solid/x-circle -->
                                                                    <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    </div>
                                                                <p class="text-sm text-red-500">
                                                                    {{ $errors->first('sshLogin') }}
                                                                </p>
                                                            </div>
                                                        @endif
                                                    </div>
                                                </div>
                                                <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                                    <div class="flex justify-between py-1">
                                                        <label for="location" class="block text-sm font-medium text-gray-700">Passphrase</label>
                                                        <span class="items-end text-sm text-gray-500" id="ssh-key-phrase">Required</span>
                                                    </div>
                                                    <div class="relative">
                                                        <input 
                                                            wire:key="sshPhrase-edit" 
                                                            type="password" 
                                                            wire:model.lazy="sshPhrase" 
                                                            placeholder="@if($errors->has('sshPhrase')){{'Please enter the passphrase'}}@endif" name="name" id="name" class="block @if($errors->has('sshPhrase')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                            aria-describedby="scan-name"
                                                        >
                                                        @if($errors->first('sshPhrase'))
                                                            <div class="flex flex-row py-1 space-x-1">
                                                                <div class="flex-shrink-0">
                                                                    <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                    </svg>
                                                                    </div>
                                                                <p class="text-sm text-red-500">
                                                                    {{ $errors->first('sshPhrase') }}
                                                                </p>
                                                            </div>
                                                        @endif
                                                    </div>
                                                </div>
                                            </div>
                                            <div>
                                                <style>
                                                    textarea {
                                                        font-family:monospace;
                                                    }
                                                </style>
                                                <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                                    <div class="flex justify-between py-1">
                                                        <label wire:key="sshKey-label-0" for="sshKey" class="block text-sm font-medium text-gray-700">Key</label>
                                                        <span wire:key="sshKey-span-0" class="items-end text-sm text-gray-500" id="ssh-key">Required</span> 
                                                    </div>
                                                    <div class="mt-1">
                                                        <textarea 
                                                            wire:key="sshKey-edit" 
                                                            wire:model.lazy="sshKey" 
                                                            placeholder="Only PKCS1 format generated with: ssh-keygen -t ecdsa -m pem" 
                                                            rows="8" 
                                                            name="sshKey" 
                                                            id="sshKey" 
                                                            class="block w-full @if($errors->has('sshKey')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
                                                        </textarea>
                                                        @if($errors->first('sshKey'))
                                                            <div class="flex flex-row py-1 space-x-1">
                                                                <div class="flex-shrink-0">
                                                                    <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                    </svg>
                                                                </div>
                                                                <p class="text-sm text-red-500">
                                                                    {{ $errors->first('sshKey') }}
                                                                </p>
                                                            </div>
                                                        @endif
                                                </div>
                                            </div>
                                            </div>
                                        @endif
                                    @endif
                                    
                                    @if($toggleSMBCredentials === 'Edit' || $toggleSMBCredentials === 'Create')
                                        <div class="py-5 mb-4 bg-white border-b border-gray-200">
                                            <h3 class="text-lg font-medium leading-6 text-gray-900">
                                                SMB Credentials
                                            </h3>
                                        </div>
    
                                        <div class="flex flex-col items-center py-4 lg:flex-row">
                                            <!-- Code block starts -->
                                            <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                                <div class="flex justify-between py-1">
                                                    <label for="location" class="block text-sm font-medium text-gray-700">Username</label>
                                                    <span class="items-end text-sm text-gray-500" id="email-optional">Required</span>
                                                </div>
                                                <div class="relative">
                                                    <input 
                                                        wire:key="smbLogin-edit" 
                                                        type="text" 
                                                        wire:model.lazy="smbLogin" 
                                                        name="smb-login" 
                                                        placeholder="@if($errors->has('smbLogin')){{'Enter username'}}@endif" id="name" class="block @if($errors->has('smbLogin')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                        aria-describedby="smb-login"
                                                    >
                                                    @if($errors->first('smbLogin'))
                                                        <div class="flex flex-row py-1 space-x-1">
                                                            <div class="flex-shrink-0">
                                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                </svg>
                                                            </div>
                                                            <p class="text-sm text-red-500">
                                                                {{ $errors->first('smbLogin') }}
                                                            </p>
                                                        </div>
                                                    @endif
                                                </div>
                                            </div>
                                            <!-- Code block ends -->
                                            <div class="flex flex-col py-4 lg:mr-16 lg:py-0">
                                                <div class="flex justify-between py-1">
                                                    <label for="location" class="block text-sm font-medium text-gray-700">Password</label>
                                                    <span class="items-end text-sm text-gray-500" id="email-optional">Required</span>
                                                </div>
                                                <div class="relative">
                                                    <input 
                                                        wire:key="smbPassword-edit" 
                                                        type="password" 
                                                        wire:model.lazy="smbPassword" 
                                                        placeholder="@if($errors->has('smbPassword')){{'Enter password'}}@endif" name="name" id="name" class="block @if($errors->has('smbPassword')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                        aria-describedby="scan-name"
                                                    >
                                                    @if($errors->first('smbPassword'))
                                                        <div class="flex flex-row py-1 space-x-1">
                                                            <div class="flex-shrink-0">
                                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                </svg>
                                                            </div>
                                                            <p class="text-sm text-red-500">
                                                                {{ $errors->first('smbPassword') }}
                                                            </p>
                                                        </div>
                                                    @endif
                                                </div>
                                            </div>
                                        </div>
                                    @endif
    
                                @elseif($currentPage === 4)

                                @if($plan === 'Free')
                                <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
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
                                                Subscribe to unlock schedules.
                                            </a>
                                        </p>
                                    </div>
                                    </div>
                                </div>
                                @endif
                                
                                    <dl class="grid grid-cols-1 py-4 gap-x-4 gap-y-8 sm:grid-cols-2">
                                        <div class="sm:col-span-1">
                                            @if($hasSchedule === 'Yes') 
                                            <dt class="text-sm font-medium text-gray-500">Schedule</dt>
                                            <dd class="mt-1 text-sm text-gray-900">
                                                <div class="flex flex-row">
                                                    @if($toggleSchedule === 'Modify')
                                                        <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                        </svg>
                                                        Modifying schedule
                                                    @elseif($toggleSchedule === 'Remove')
                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                        </svg>
                                                        Schedule removed
                                                    @elseif($toggleSchedule != 'Modify' && $hasSchedule === 'Yes' && $toggleSchedule != 'Remove')
                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                        </svg>
                                                        Schedule configured
                                                    @endif
                                                </div>
                                            </dd>
                                            @else
                                            <dt class="text-sm font-medium text-gray-500">
                                                Schedule 
                                            </dt>
                                            <dd class="mt-1 text-sm text-gray-900">
                                                <div class="flex flex-row">
                                                    @if($toggleSchedule === 'Create')
                                                        @if(is_null($scheduleStartDate) || 
                                                            is_null($scheduleFrequency) || 
                                                            $scheduleFrequency == "" || 
                                                            $scheduleStartDate == ""
                                                            )
                                                            <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                            </svg>
                                                            &nbsp; Add a schedule
                                                        @elseif(!is_null($scheduleStartDate) && !is_null($scheduleFrequency))
                                                            <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                            </svg>
                                                            &nbsp; Schedule configured
                                                        @endif
                                                    @elseif($toggleSchedule != 'Create' && $hasSchedule === 'Yes' && $toggleSchedule != 'Remove')
                                                        <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                        </svg>
                                                        &nbsp; Schedule configured
                                                    @else
                                                        <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                        </svg>
                                                        &nbsp; No schedule configured
                                                    @endif
                                                </div>
                                            </dd>
                                            @endif
                                        </div>
                                        <div class="sm:col-span-1">
                                            <select 
                                                @if($plan === 'Free') {{ 'disabled' }} @endif
                                                wire:key="toggleSchedule-edit" 
                                                wire:model="toggleSchedule" 
                                                id="toggleSchedule" 
                                                name="toggleSchedule" 
                                                class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                            >
                                                @if($this->hasSchedule === 'Yes') 
                                                    <option selected value="">Select option...</option>
                                                    <option value="Modify">Modify</option>
                                                    <option value="Remove">Remove</option>
                                                @else
                                                    <option selected value="">Select Option</option>
                                                    <option value="Create">Create</option>
                                                @endif
                                            </select>
                                        </div>
                                    </dl>
    
                                    @if($toggleSchedule === 'Create' || $toggleSchedule === 'Modify')
                                        <dl class="grid grid-cols-1 py-4 gap-x-4 gap-y-8 sm:grid-cols-2">
                                            <div class="sm:col-span-1">
                                                <dt class="text-sm font-medium text-gray-500">
                                                    Start
                                                </dt>
                                                <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                    <dd class="text-sm text-gray-900">UTC Timezone</dd>
                                                </div>
                                            </div>
                                            <div class="sm:col-span-1">
                                                <div class="relative">
                                                    <x-input.datetime-picker 
                                                        wire:key="scheduleStartDate-edit" 
                                                        wire:model="scheduleStartDate" 
                                                        class="w-full border-gray-300 rounded-md shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50" 
                                                    />
                                                    @if($errors->first('scheduleStartDate'))
                                                        <div class="flex flex-row py-1 space-x-1">
                                                            <div class="flex-shrink-0">
                                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                </svg>
                                                            </div>
                                                            <p class="text-sm text-red-500">
                                                                {{ $errors->first('scheduleStartDate') }}
                                                            </p>
                                                        </div>
                                                    @endif
                                                </div>
                                            </div>
                                        </dl>
                                        <dl class="grid grid-cols-1 py-4 gap-x-4 gap-y-8 sm:grid-cols-2">
                                            <div class="sm:col-span-1">
                                                <dt class="text-sm font-medium text-gray-500">
                                                    Frequency
                                                </dt>
                                                <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                    <dd class="text-sm text-gray-900">The frequency at which a schedule has to be repeated</dd>
                                                </div>
                                            </div>
                                            <div class="sm:col-span-1">
                                                <div class="relative">
                                                    <select 
                                                        wire:key="scheduleFrequency-edit" 
                                                        wire:model="scheduleFrequency" 
                                                        id="schedule-frequency" 
                                                        name="schedule-frequency" 
                                                        class="block py-2 pl-3 pr-10 mt-1 text-base border-gray-300 rounded-md js-example-basic-single w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                    >
                                                        <option selected value="">Select Frequency</option>
                                                        <option value="ONCE">Once</option>
                                                        <option value="HOURLY">Hourly</option>
                                                        <option value="DAILY">Daily</option>
                                                        <option value="WEEKLY">Weekly</option>
                                                        <option value="WORKWEEK">Workweek</option>
                                                        <option value="MONTHLY">Monthly</option>
                                                    </select>
                                                    @if($errors->first('scheduleFrequency'))
                                                        <div class="flex flex-row py-1 space-x-1">
                                                            <div class="flex-shrink-0">
                                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                </svg>
                                                            </div>
                                                            <p class="text-sm text-red-500">
                                                                {{ $errors->first('scheduleFrequency') }}
                                                            </p>
                                                        </div>
                                                    @endif
                                                </div>
                                            </div>
                                        </dl>
                                    @endif
                                        
                                @elseif($currentPage === 5)

                                @if($plan === 'Free')
                                <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
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
                                                Subscribe to unlock schedules.
                                            </a>
                                        </p>
                                    </div>
                                    </div>
                                </div>
                                @endif

                                <div class="mt-1 overflow-hidden bg-white sm:rounded-lg">
                                    <div class="py-5">
                                        <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                            <div class="sm:col-span-1">
                                                <dt class="text-sm font-medium text-gray-500">
                                                    Email notification
                                                </dt>
                                                <dd class="mt-1 text-sm text-gray-900">
                                                    <div class="flex flex-row">
                                                        @if($toggleNotification === 'Create' && !empty($this->email))
                                                            @if(!$errors->has($email))
                                                                <svg class="w-5 h-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                                </svg>
                                                                &nbsp; Notification configured
                                                            @endif
                                                        @elseif($toggleNotification != 'Create' && $hasNotification === 'Yes' && $toggleNotification != 'Remove')
                                                            <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                            </svg>
                                                            &nbsp; Notification configured
                                                        @elseif($toggleNotification === 'Remove')
                                                            <svg class="flex-shrink-0 mr-1.5 h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                                                            </svg>
                                                            &nbsp; Notification removed
                                                        @else
                                                            <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
                                                            </svg>
                                                            &nbsp; Notification not configured
                                                        @endif
                                                    </div>
                                                </dd>
                                            </div>
                                            <div class="sm:col-span-1">
                                                @if($hasNotification === 'Yes')
                                                    <select 
                                                        @if($plan === 'Free') {{ 'disabled' }} @endif
                                                        wire:key="toggleNotification-0" 
                                                        wire:model="toggleNotification" 
                                                        id="toggleNotification" 
                                                        name="toggleNotification" 
                                                        class="block py-2 pl-3 pr-10 mt-1 text-base @if($errors->has('toggleNotification')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                    >
                                                        <option value="" selected>Select Option</option>
                                                        <option value="Edit">Edit</option>
                                                        <option value="Remove">Remove</option>
                                                    </select>
                                                @else
                                                    <select 
                                                        wire:key="toggleNotification-0" 
                                                        wire:model="toggleNotification" 
                                                        id="toggleNotification" 
                                                        name="toggleNotification" 
                                                        class="block py-2 pl-3 pr-10 mt-1 text-base @if($errors->has('toggleNotification')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md w-80 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
                                                    >
                                                        <option value="" selected>Select Option</option>
                                                        <option value="Create">Create</option>
                                                    </select>
                                                @endif
                                            </div>
                                        </dl>
                                    </div>
                                </div>
                                
                                @if($toggleNotification === 'Edit' || $toggleNotification === 'Create')
                                    <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                        <div class="sm:col-span-1">
                                            <dt class="mt-4 text-sm font-medium text-gray-500">
                                                Email
                                            </dt>
                                            <div class="flex flex-row flex-shrink-0 mt-1 space-x-2">
                                                <dd class="text-sm text-gray-900">Email address that will receive the notification</dd>
                                            </div>
                                        </div>
                                        <div class="sm:col-span-1">
                                            <div class="flex flex-col items-start py-4">
                                                <div class="flex flex-col py-4 lg:mr-3 lg:py-0">
                                                    <div class="sm:col-span-1">
                                                        
                                                        <input 
                                                            wire:key="email-edit" 
                                                            type="email" 
                                                            id="email"
                                                            autocomplete="email"
                                                            wire:model.lazy="email" 
                                                            class="block @if($errors->has('email')){{'border-red-300'}}@else{{'border-gray-300'}}@endif rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
                                                            aria-describedby="scan-name"
                                                        >
                                                    </div>
                                                    @if($errors->first('email'))
                                                        <div class="flex flex-row py-1 space-x-1">
                                                            <div class="flex-shrink-0">
                                                                <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                                                </svg>
                                                            </div>
                                                            <p class="text-sm text-red-500">
                                                                {{ $errors->first('email') }}
                                                            </p>
                                                        </div>
                                                    @endif
                                                </div>
                                            </div>
                                        </div>
                                    </dl>
                                @endif
    
                                @elseif($currentPage === 6)
                                    <div class="py-4">
                                        <div>
                                            <h3 class="text-lg font-medium leading-6 text-gray-900">
                                                Scan Information
                                            </h3>
                                            <p class="max-w-2xl mt-1 text-sm text-gray-500">
                                                Scan details and configuration
                                            </p>
                                        </div>
                                        <div class="mt-5 border-t border-gray-200">
                                            <dl class="sm:divide-y sm:divide-gray-200">
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Name
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        {{ $scanName }}
                                                    </dd>
                                                </div>
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Description
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        {{ $scanDescription }}
                                                    </dd>
                                                </div>
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Targets Included
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        {{ $targetList }}
                                                    </dd>
                                                </div>
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Targets Excluded
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        @if($toggleExcludeTargets === 'No')
                                                            {{ 'No targets excluded from the assets in scope' }}
                                                        @else
                                                            {{ $targetExclude }}
                                                        @endif
                                                    </dd>
                                                </div>
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Port Scanning
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        @if($targetPorts === 'fd591a34-56fd-11e1-9f27-406186ea4fc5')
                                                            {{ 'All TCP Ports from 1 to 65535' }}
                                                        @elseif($targetPorts === 'ab33f6b0-57f8-11e1-96f5-406186ea4fc5')
                                                            {{ 'Top TCP and UDP Ports' }}
                                                        @elseif($targetPorts === '730ef368-57e2-11e1-a90f-406186ea4fc5')
                                                            {{ 'All TCP Ports from 1 to 65535 and Top UDP ports' }}
                                                        @elseif($targetPorts === 'customports')
                                                            {{ $portRange }}
                                                        @endif
                                                    </dd>
                                                </div>
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Host Discovery
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        @if($targetAlive == '2')
                                                            {{ 'ARP Ping' }}
                                                        @elseif($targetAlive == '1')
                                                            {{ 'ICMP Ping' }}
                                                        @elseif($targetAlive == '6')
                                                            {{ 'TCP-ACK Ping' }}
                                                        @elseif($targetAlive == '7')
                                                            {{ 'TCP-SYN Ping' }}
                                                        @elseif($targetAlive == '5')
                                                            {{ 'Consider Alive' }}
                                                        @elseif($targetAlive == '8')
                                                            {{ 'ICMP and ARP Ping' }}
                                                        @elseif($targetAlive == '9')
                                                            {{ 'TCP-ACK and ARP Ping' }}
                                                        @elseif($targetAlive == '16')
                                                            {{ 'TCP-SYN Service Ping' }}
                                                        @elseif($targetAlive == '4')
                                                            {{ 'ICMP and TCP-ACK Ping' }}
                                                        @elseif($targetAlive == '3')
                                                            {{ 'ICMP, TCP-ACK and ARP Ping' }}
                                                        @endif
                                                    </dd>
                                                </div>
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Speed
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        @if($scanSpeed == '1')
                                                            {{ 'Good for slow networks' }}
                                                        @elseif($scanSpeed == '3')
                                                            {{ 'Good for fast networks' }}
                                                        @elseif($scanSpeed == '2')
                                                            {{ 'Good for normal networks' }}
                                                        @endif
                                                    </dd>
                                                </div>
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Credentials
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        <div class="flex flex-row space-x-2">
                                                        @if($toggleSSHCredentials === 'Create' || 
                                                            $toggleSSHCredentials === 'Modify' || 
                                                            $toggleSSHCredentials === 'Edit')
                                                            
                                                            <span class="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800">
                                                                SSH Credential
                                                            </span>
                                                        @elseif($hasSSHCredentials === 'Yes' && $toggleSSHCredentials != 'Remove')
                                                            <span class="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800">
                                                                SSH Credential
                                                            </span>
                                                        @endif
                                                        
                                                        @if($toggleSMBCredentials === 'Create' || 
                                                            $toggleSMBCredentials === 'Modify' || 
                                                            $toggleSMBCredentials === 'Edit' )
                                                            
                                                            <span class="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800">
                                                                SMB Credential
                                                            </span>
                                                        @elseif($hasSMBCredentials === 'Yes' && $toggleSMBCredentials != 'Remove')
                                                            <span class="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-800">
                                                                SMB Credential
                                                            </span>
                                                        @endif
                                                        
                                                            @if($toggleSMBCredentials === 'Remove' || is_null($smbLogin))
                                                            <span class="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                                                               No SMB Credential
                                                            </span>
                                                            @endif

                                                            @if($toggleSSHCredentials === 'Remove' || is_null($sshLogin))
                                                            <span class="inline-flex items-center px-3 py-0.5 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                                                                No SSH Credential
                                                            </span>
                                                            @endif
                                                            
                                                        </div>
                                                    </dd>
                                                </div>
                                                <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                    <dt class="text-sm font-medium text-gray-500">
                                                        Schedule
                                                    </dt>
                                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                        @if($toggleSchedule === 'Create' ||
                                                            $toggleSchedule === 'Modify' || 
                                                            $toggleSchedule == "" && !empty($toggleSchedule))
                                                            <ul>
                                                                <li>Timezone: UTC</li>
                                                                <li>Frequency: @if($scheduleFrequency === 'WEEKLY')
                                                                    {{ 'Weekly' }}
                                                                    @elseif($scheduleFrequency === 'DAILY')
                                                                        {{ 'Daily' }}
                                                                    @elseif($scheduleFrequency === 'ONCE')
                                                                        {{ 'Once' }}
                                                                    @elseif($scheduleFrequency === 'MONTHLY')
                                                                        {{ 'Monthly' }}
                                                                    @elseif($scheduleFrequency === 'WORKWEEK')
                                                                        {{ 'Workweek' }}
                                                                    @elseif($scheduleFrequency === 'HOURLY')
                                                                        {{ 'Hourly' }}
                                                                    @endif
                                                                </li>
                                                                <li>Starts: {{ $scheduleStartDate }}</li>
                                                            </ul>
                                                        @elseif($toggleSchedule === 'Remove')
                                                            {{ 'Schedule removed' }}
                                                        @elseif($hasSchedule === 'Yes')
                                                            {{ 'Scheduled' }}
                                                        @else
                                                            {{ 'Unscheduled' }}
                                                        @endif
                                                    </dd>
                                                </div>
                                                @if(!empty($email))
                                                    <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4">
                                                        <dt class="text-sm font-medium text-gray-500">
                                                            Notification 
                                                        </dt>
                                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                                            {{ $email }}
                                                        </dd>
                                                    </div>
                                                @endif
                                            </dl>
                                        </div>
                                    </div>
                                @endif
                            </x-slot>
    
                            <x-slot name="footer">
                                <div class="flex items-center justify-between">
                                    @if($currentPage === 1)
                                        <x-jet-secondary-button wire:click="closeEditModal">Cancel</x-jet-secondary-button>
                                    @elseif($currentPage <= 6)
                                        <x-jet-secondary-button wire:click="backPage">Back</x-jet-secondary-button>
                                    @endif
    
                                    @if($currentPage === 1)
                                        <x-jet-button class="ml-2" wire:click="firstStepSubmit">Next</x-jet-button>
                                    @elseif($currentPage === 2)
                                        <x-jet-button class="ml-2" wire:click="secondStepSubmit">Next</x-jet-button>
                                    @elseif($currentPage === 3)
                                        <x-jet-button class="ml-2" wire:click="thirdStepSubmit">Next</x-jet-button>
                                    @elseif($currentPage === 4)
                                        <x-jet-button class="ml-2" wire:click="fourthStepSubmit">Next</x-jet-button>
                                    @elseif($currentPage === 5)
                                        <x-jet-button class="ml-2" wire:click="fifthStepSubmit">Next</x-jet-button>
                                    @elseif($currentPage === 6)
                                        <x-jet-button class="ml-2" wire:click="saveEditScan">Save</x-jet-button>
                                    @endif
                                </div>
                            </x-slot>
                        </x-modal.dialog>
                    </div>
                @endif

            </div>
        </div>
    </main>
</div>
@push('swal')
<script>
    Livewire.on('scan-created', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            timer: e.timer,
            toast: false,
            width: 600,
            padding: '3em',
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })
    
    Livewire.on('scan-start', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            timer: e.timer,
            toast: false,
            width: 600,
            padding: '3em',
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })

    Livewire.on('scan-stop', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            timer: e.timer,
            toast: false,
            width: 600,
            padding: '3em',
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })

    Livewire.on('scan-resume', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            timer: e.timer,
            toast: false,
            width: 600,
            padding: '3em',
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })

    Livewire.on('scan-deleted', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            timer: e.timer,
            toast: false,
            width: 600,
            padding: '3em',
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })

    Livewire.on('scan-modified', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            timer: e.timer,
            toast: false,
            width: 600,
            padding: '3em',
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })

    Livewire.on('error-modifying-scan', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            showConfirmButton: true,
            confirmButtonText: 'Close',
            text: e.text,
            toast: false,
            width: 600,
            padding: '3em',
            timerProgressBar: true,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })

    Livewire.on('scan-clone', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            timer: e.timer,
            toast: false,
            width: 600,
            padding: '3em',
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })

    Livewire.on('scan-unlock', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            width: 600,
            padding: '3em',
            timer: e.timer,
            toast: false,
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })

    Livewire.on('scan-lock', function(e) {
        Swal.fire({
            title: e.title,
            icon: e.icon,
            iconColor: e.iconColor,
            width: 600,
            padding: '3em',
            timer: e.timer,
            toast: false,
            timerProgressBar: true,
            showConfirmButton: false,
            showClass: {
                popup: 'animate__animated animate__fadeIn'
            },
            hideClass: {
                popup: 'animate__animated animate__fadeOut'
            }
        })
    })
</script>
@endpush