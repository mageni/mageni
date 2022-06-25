<div>
    <x-headers.reports />

    <main class="py-10">
        <div class="max-w-full mx-auto sm:px-6 lg:px-6">

            <div>
                <h3 class="text-lg font-medium leading-6 text-gray-900">Vulnerabilities</h3>
                <dl class="grid grid-cols-1 gap-5 mt-5 sm:grid-cols-4">
                
                    <div class="px-4 py-5 overflow-hidden bg-white rounded-lg shadow sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Critical</dt>
                        @if(!is_null($criticalvuln))
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">{{ $criticalvuln }}</dd>
                        @else
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">0</dd>
                        @endif
                    </div>
                
                    <div class="px-4 py-5 overflow-hidden bg-white rounded-lg shadow sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">High</dt>
                        @if(!is_null($highvuln))
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">{{ $highvuln }}</dd>
                        @else
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">0</dd>
                        @endif
                    </div>

                    <div class="px-4 py-5 overflow-hidden bg-white rounded-lg shadow sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Medium</dt>
                        @if(!is_null($mediumvuln))
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">{{ $mediumvuln }}</dd>
                        @else
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">0</dd>
                        @endif
                    </div>

                    <div class="px-4 py-5 overflow-hidden bg-white rounded-lg shadow sm:p-6">
                        <dt class="text-sm font-medium text-gray-500 truncate">Low</dt>
                        @if(!is_null($lowvuln))
                            <dd class="mt-1 text-3xl font-semibold text-gray-900">{{ $lowvuln }}</dd>
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
                                
                        </div>
                        <div class="flex justify-between space-x-2">
                            <div>
                                @if($selectPage || $selected)
                                    <div>
                                        <x-jet-button wire:click="exportSelected" class="hover:shadow">
                                            Download CSV
                                        </x-jet-button>
                                    </div>
                                @else

                                    <x-jet-button wire:click="exportReport" wire:loading.class="invisible" class="hover:shadow">
                                        Download Report
                                    </x-jet-button>

                                    <div wire:loading wire:target="exportReport" class="text-sm text-gray-700">
                                        <div class="flex flex-row space-x-4 mt-3">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 animate-spin mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                              </svg>
                                            Please wait...
                                        </div>
                                    </div>
                                @endif
                            </div>
                        </div>
                    </div>
                    <div>
                </div>
            </div>

            <x-table class="table-auto">
                <x-slot name="head">
                    <x-table.heading class="w-6 pr-0">
                        <x-input.checkbox wire:model="selectPage" class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"/>
                    </x-table.heading>
                    <x-table.heading sortable wire:click="sortBy('name')" :direction="$sortField === 'name' ? $sortDirection : null">Name</x-table.heading>
                    <x-table.heading sortable wire:click="sortBy('cvss')" :direction="$sortField === 'cvss' ? $sortDirection : null">Severity</x-table.heading>
                    <x-table.heading sortable wire:click="sortBy('cvss')" :direction="$sortField === 'cvss' ? $sortDirection : null">CVSS</x-table.heading>
                    <x-table.heading sortable wire:click="sortBy('hostcount')" :direction="$sortField === 'hostcount' ? $sortDirection : null">Hosts</x-table.heading>
                    <x-table.heading sortable wire:click="sortBy('family')" :direction="$sortField === 'family' ? $sortDirection : null">Category</x-table.heading>
                    {{-- <x-table.heading sortable></x-table.heading> --}}
                </x-slot>
                <x-slot name="body">
                    <div>
                        @if($selectPage || $selected)
                            <x-table.row class="bg-gray-200" wire:key="row-message">
                                <x-table.cell colspan="100%">
                                    @unless($selectAll)
                                        <div>
                                            <span>You have selected <strong>{{ count($selected) }}</strong> tasks, do you want select all <strong>{{ $details->total() }}</strong>?</span>
                                            <x-button.link wire:click="selectAll" class="ml-1 text-blue-500">Select All</x-button.link>
                                        </div>
                                    @else
                                        <div>
                                            <span>You have selected all <strong>{{ $details->total() }}</strong> tasks. <x-button.link wire:click="unSelectAll" class="ml-1 text-blue-500">UnSelect All</x-button.link></span>
                                        </div>
                                    @endif
                                </x-table.cell>
                            </x-table.row>
                        @endif
                    </div>
                    <div>
                        @if(!is_null($details))
                            @foreach($details as $detail)
                                <x-table.row wire:loading.delay.class="opacity-50" wire:target="search">
                                    <x-table.cell class="pr-0">
                                        <div wire:key="{{ $loop->index }}">
                                            @if($detail->run_status == 4 || $detail->run_status == 3)
                                                <input wire:key="{{ $loop->index }}" id="tasks" aria-describedby="checkbox" name="checkbox" type="checkbox" class="w-4 h-4 text-blue-600 border-gray-300 rounded cursor-not-allowed focus:ring-blue-500" disabled>
                                            @else
                                                <input wire:key="{{ $loop->index }}" wire:model="selected" value="{{ $detail->id }}" id="tasks" aria-describedby="tasks-id" name="tasks" type="checkbox" class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500">
                                            @endif
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div wire:key="{{ $loop->index }}">
                                            <div class="flex items-center">
                                                <div class="flex-shrink-0 w-10 h-10">
                                                    @if($detail->cvss >= '9.0')
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-10 text-pink-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                            <path stroke-linecap="round" stroke-linejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                                                        </svg>
                                                    @elseif($detail->cvss >= '7.0' && $detail->cvss < '8.9')
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-10 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                            <path stroke-linecap="round" stroke-linejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                                                        </svg>
                                                    @elseif($detail->cvss >= '4.0' && $detail->cvss <= '6.9')
                                                        <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-10 text-orange-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                            <path stroke-linecap="round" stroke-linejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                                                        </svg>
                                                    @elseif($detail->cvss >= '0.1' && $detail->cvss <= '3.9')
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-10 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                                                    </svg>
                                                    @elseif($detail->cvss < '0.1')
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-10 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                                                    </svg>
                                                    @endif
                                                </div>
                                                <div>
                                                    <div class="font-medium text-gray-900">
                                                        <x-button.link                                                     wire:click="vulnDetails('{{$detail->nvt}}')"
                                                            class="font-semibold text-gray-600 hover:underline hover:text-blue-600">
                                                            {{ $detail->name }}
                                                        </x-button.link>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div wire:key="{{ $loop->index }}" class="flex items-center space-x-3">
                                            @if($detail->cvss >= '9.0')
                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-pink-700 text-pink-100 md:mt-2 lg:mt-0">
                                                    Critical
                                                </div>
                                            @elseif($detail->cvss >= '7.0' && $detail->cvss < '8.9')
                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-red-100 text-red-800 md:mt-2 lg:mt-0">
                                                    High
                                                </div>
                                            @elseif($detail->cvss >= '4.0' && $detail->cvss <= '6.9')
                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-orange-100 text-orange-700 md:mt-2 lg:mt-0">
                                                    Medium
                                                </div>
                                            @elseif($detail->cvss >= '0.1' && $detail->cvss <= '3.9')
                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-700 md:mt-2 lg:mt-0">
                                                    Low
                                                </div>
                                            @elseif($detail->cvss < '0.1')
                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-blue-100 text-blue-700 md:mt-2 lg:mt-0">
                                                    Log
                                                </div>
                                            @else
                                                {{ $detail->CVSS }}
                                            @endif
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div wire:key="{{ $loop->index }}">
                                            {{ $detail->cvss }}
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div wire:key="{{ $loop->index }}">
                                            {{ $detail->hostcount }}
                                        </div>
                                    </x-table.cell>
                                    <x-table.cell>
                                        <div wire:key="{{ $loop->index }}" class="inline-flex space-x-2 text-sm leading-5 truncate">
                                            <span wire:key="{{ $loop->index }}">
                                                {{ $detail->category }}
                                            </span>
                                        </div>
                                    </x-table.cell>
                                    {{-- <x-table.cell>
                                        <div class="flex flex-row justify-end space-x-3">
                                            <div>
                                                <i 
                                                    wire:key="{{ $loop->index }}" 
                                                    wire:click="deleteShowModal('{{$detail->uuid}}')" 
                                                    class="text-red-600 cursor-pointer far fa-trash-alt fa-lg hover:text-red-900" 
                                                    x-data
                                                    x-tooltip="Delete"
                                                >
                                                </i>
                                            </div>
                                        </div>
                                    </x-table.cell> --}}
                                </x-table.row>
                            @endforeach
                        @else
                    </div>
                        <x-table.row>
                            <x-table.cell class="px-6 py-4 whitespace-nowrap" colspan="100%">
                                <span class="flex items-center justify-center space-x-2 text-lg font-medium text-gray-400">
                                    <i class="mr-2 fas fa-binoculars"></i>
                                    No reports found.
                                </span>
                            </x-table.cell>
                        </x-table.row>
                    @endif
                </x-slot>
            </x-table>
                <div class="mt-2">
                    {{ $details->links() }}
                </div>
        </div>
    </main>

</div>
