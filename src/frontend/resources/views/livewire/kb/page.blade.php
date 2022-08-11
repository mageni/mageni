<div>
    <x-headers.kb/>
    <div x-data="{ tab: window.location.hash ? window.location.hash.substring(1) : 'vulnerabilities' }" id="tab_wrapper">
        <main class="py-10" wire:poll.keep-alive>
            <!-- Page header -->
            <div class="max-w-full mx-auto pr-4 sm:px-6 md:flex md:items-center md:justify-between md:space-x-5 lg:max-w-full lg:px-6">
                <div class="flex items-center space-x-5">
                    <div>
                        <h1 class="text-2xl font-bold text-gray-900">Knowledge Base</h1>
                        <p class="text-sm font-medium text-gray-500">Updated: {{ $creationTime->creation_time->diffForHumans() }}</p>
                    </div>
                </div>
                {{--            <div class="mt-6 flex flex-col-reverse justify-stretch space-y-4 space-y-reverse sm:flex-row-reverse sm:justify-end sm:space-x-reverse sm:space-y-0 sm:space-x-3 md:mt-0 md:flex-row md:space-x-3">--}}
                {{--                <button type="button" class="inline-flex items-center justify-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100 focus:ring-blue-500">--}}
                {{--                    Disqualify--}}
                {{--                </button>--}}
                {{--                <button type="button" class="inline-flex items-center justify-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-100 focus:ring-blue-500">--}}
                {{--                    Advance to offer--}}
                {{--                </button>--}}
                {{--            </div>--}}
            </div>

            {{--        <div class="max-w-full lg:max-w-full lg:px-6 mt-5">--}}
            {{--            <div>--}}
            {{--                <dl class="mt-5 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">--}}
            {{--                    <div class="relative bg-white pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">--}}
            {{--                        <dt>--}}
            {{--                            <div class="absolute bg-indigo-500 rounded-md p-3">--}}
            {{--                                <!-- Heroicon name: outline/users -->--}}
            {{--                                <svg class="h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">--}}
            {{--                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />--}}
            {{--                                </svg>--}}
            {{--                            </div>--}}
            {{--                            <p class="ml-16 text-sm font-medium text-gray-500 truncate">Total Subscribers</p>--}}
            {{--                        </dt>--}}
            {{--                        <dd class="ml-16 pb-6 flex items-baseline sm:pb-7">--}}
            {{--                            <p class="text-2xl font-semibold text-gray-900">--}}
            {{--                                71,897--}}
            {{--                            </p>--}}
            {{--                            <p class="ml-2 flex items-baseline text-sm font-semibold text-green-600">--}}
            {{--                                <!-- Heroicon name: solid/arrow-sm-up -->--}}
            {{--                                <svg class="self-center flex-shrink-0 h-5 w-5 text-green-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">--}}
            {{--                                    <path fill-rule="evenodd" d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z" clip-rule="evenodd" />--}}
            {{--                                </svg>--}}
            {{--                                <span class="sr-only">--}}
            {{--                                    Increased by--}}
            {{--                                </span>--}}
            {{--                                    122--}}
            {{--                            </p>--}}
            {{--                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">--}}
            {{--                                <div class="text-sm">--}}
            {{--                                    <a :class="{ 'active': tab === 'vulnerabilities' }" @click.prevent="tab = 'vulnerabilities'; window.location.hash = 'vulnerabilities'" href="#" class="font-medium text-indigo-600 hover:text-indigo-500"> View all<span class="sr-only"> Total Subscribers stats</span></a>--}}
            {{--                                </div>--}}
            {{--                            </div>--}}
            {{--                        </dd>--}}
            {{--                    </div>--}}

            {{--                    <div class="relative bg-white pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">--}}
            {{--                        <dt>--}}
            {{--                            <div class="absolute bg-indigo-500 rounded-md p-3">--}}
            {{--                                <!-- Heroicon name: outline/mail-open -->--}}
            {{--                                <svg class="h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">--}}
            {{--                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 19v-8.93a2 2 0 01.89-1.664l7-4.666a2 2 0 012.22 0l7 4.666A2 2 0 0121 10.07V19M3 19a2 2 0 002 2h14a2 2 0 002-2M3 19l6.75-4.5M21 19l-6.75-4.5M3 10l6.75 4.5M21 10l-6.75 4.5m0 0l-1.14.76a2 2 0 01-2.22 0l-1.14-.76" />--}}
            {{--                                </svg>--}}
            {{--                            </div>--}}
            {{--                            <p class="ml-16 text-sm font-medium text-gray-500 truncate">Avg. Open Rate</p>--}}
            {{--                        </dt>--}}
            {{--                        <dd class="ml-16 pb-6 flex items-baseline sm:pb-7">--}}
            {{--                            <p class="text-2xl font-semibold text-gray-900">--}}
            {{--                                58.16%--}}
            {{--                            </p>--}}
            {{--                            <p class="ml-2 flex items-baseline text-sm font-semibold text-green-600">--}}
            {{--                                <!-- Heroicon name: solid/arrow-sm-up -->--}}
            {{--                                <svg class="self-center flex-shrink-0 h-5 w-5 text-green-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">--}}
            {{--                                    <path fill-rule="evenodd" d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z" clip-rule="evenodd" />--}}
            {{--                                </svg>--}}
            {{--                                <span class="sr-only">--}}
            {{--                                    Increased by--}}
            {{--                                </span>--}}
            {{--                                    5.4%--}}
            {{--                            </p>--}}
            {{--                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">--}}
            {{--                                <div class="text-sm">--}}
            {{--                                    <a :class="{ 'active': tab === 'assets' }" @click.prevent="tab = 'assets'; window.location.hash = 'assets'" href="#" class="font-medium text-indigo-600 hover:text-indigo-500"> View all<span class="sr-only"> Avg. Open Rate stats</span></a>--}}
            {{--                                </div>--}}
            {{--                            </div>--}}
            {{--                        </dd>--}}
            {{--                    </div>--}}

            {{--                    <div class="relative bg-white pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">--}}
            {{--                        <dt>--}}
            {{--                            <div class="absolute bg-indigo-500 rounded-md p-3">--}}
            {{--                                <!-- Heroicon name: outline/mail-open -->--}}
            {{--                                <svg class="h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">--}}
            {{--                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 19v-8.93a2 2 0 01.89-1.664l7-4.666a2 2 0 012.22 0l7 4.666A2 2 0 0121 10.07V19M3 19a2 2 0 002 2h14a2 2 0 002-2M3 19l6.75-4.5M21 19l-6.75-4.5M3 10l6.75 4.5M21 10l-6.75 4.5m0 0l-1.14.76a2 2 0 01-2.22 0l-1.14-.76" />--}}
            {{--                                </svg>--}}
            {{--                            </div>--}}
            {{--                            <p class="ml-16 text-sm font-medium text-gray-500 truncate">Avg. Open Rate</p>--}}
            {{--                        </dt>--}}
            {{--                        <dd class="ml-16 pb-6 flex items-baseline sm:pb-7">--}}
            {{--                            <p class="text-2xl font-semibold text-gray-900">--}}
            {{--                                58.16%--}}
            {{--                            </p>--}}
            {{--                            <p class="ml-2 flex items-baseline text-sm font-semibold text-green-600">--}}
            {{--                                <!-- Heroicon name: solid/arrow-sm-up -->--}}
            {{--                                <svg class="self-center flex-shrink-0 h-5 w-5 text-green-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">--}}
            {{--                                    <path fill-rule="evenodd" d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z" clip-rule="evenodd" />--}}
            {{--                                </svg>--}}
            {{--                                <span class="sr-only">--}}
            {{--                                    Increased by--}}
            {{--                                </span>--}}
            {{--                                    5.4%--}}
            {{--                            </p>--}}
            {{--                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">--}}
            {{--                                <div class="text-sm">--}}
            {{--                                    <a :class="{ 'active': tab === 'history' }" @click.prevent="tab = 'history'; window.location.hash = 'history'" href="#" class="font-medium text-indigo-600 hover:text-indigo-500"> View all<span class="sr-only"> Avg. Open Rate stats</span></a>--}}
            {{--                                </div>--}}
            {{--                            </div>--}}
            {{--                        </dd>--}}
            {{--                    </div>--}}

            {{--                    <div class="relative bg-white pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">--}}
            {{--                        <dt>--}}
            {{--                            <div class="absolute bg-indigo-500 rounded-md p-3">--}}
            {{--                                <!-- Heroicon name: outline/cursor-click -->--}}
            {{--                                <svg class="h-6 w-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">--}}
            {{--                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" />--}}
            {{--                                </svg>--}}
            {{--                            </div>--}}
            {{--                            <p class="ml-16 text-sm font-medium text-gray-500 truncate">Avg. Click Rate</p>--}}
            {{--                        </dt>--}}
            {{--                        <dd class="ml-16 pb-6 flex items-baseline sm:pb-7">--}}
            {{--                            <p class="text-2xl font-semibold text-gray-900">--}}
            {{--                                24.57%--}}
            {{--                            </p>--}}
            {{--                            <p class="ml-2 flex items-baseline text-sm font-semibold text-red-600">--}}
            {{--                                <!-- Heroicon name: solid/arrow-sm-down -->--}}
            {{--                                <svg class="self-center flex-shrink-0 h-5 w-5 text-red-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">--}}
            {{--                                    <path fill-rule="evenodd" d="M14.707 10.293a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 12.586V5a1 1 0 012 0v7.586l2.293-2.293a1 1 0 011.414 0z" clip-rule="evenodd" />--}}
            {{--                                </svg>--}}
            {{--                                <span class="sr-only">--}}
            {{--                                    Decreased by--}}
            {{--                                </span>--}}
            {{--                                    3.2%--}}
            {{--                            </p>--}}
            {{--                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">--}}
            {{--                                <div class="text-sm">--}}
            {{--                                    <a href="#" class="font-medium text-indigo-600 hover:text-indigo-500"> View all<span class="sr-only"> Avg. Click Rate stats</span></a>--}}
            {{--                                </div>--}}
            {{--                            </div>--}}
            {{--                        </dd>--}}
            {{--                    </div>--}}
            {{--                </dl>--}}
            {{--            </div>--}}
            {{--        </div>--}}

            <div class="mt-8 max-w-full mx-auto grid grid-cols-3 gap-6 sm:px-6 lg:max-w-full lg:grid-flow-col-dense lg:grid-cols-3">
                <div class="space-y-6 lg:col-start-1 lg:col-span-3">
                    <section aria-labelledby="applicant-information-title">
                        <div>
                            <div class="px-3 py-5 bg-white">
{{--                                <h3 class="text-lg leading-6 font-medium text-gray-900">--}}
{{--                                    Scan Findings {{ $creationTime->creation_time }}--}}
{{--                                </h3>--}}
{{--                                <p class="mt-1 max-w-2xl text-sm text-gray-500">--}}
{{--                                    Vulnerabilities found by the scan--}}
{{--                                </p>--}}
                            </div>

                            <div
                                class="origin-top"
                                x-show="tab === 'vulnerabilities'"
                            >
                                <div class="space-y-4 bg-white">
                                    <div class="mr-3 ml-1 sm:flex sm:items-center sm:justify-between">
                                        <div class="relative flex w-2/4 ml-1">
                                            <svg width="20" height="20" fill="currentColor" class="absolute text-gray-400 transform -translate-y-1/2 left-2 top-1/2">
                                                <path fill-rule="evenodd" clip-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" />
                                            </svg>
                                            <x-input.text
                                                id="name"
                                                wire:model="search"
                                                type="text"
                                                class="block w-full pl-8 text-sm text-black placeholder-gray-500 border border-gray-200 rounded-md focus:border-light-blue-500 focus:ring-1 focus:ring-light-blue-500 focus:outline-none"
                                                autofocus
                                                placeholder="Search"
                                            />
{{--                                            <x-button.link class="ml-4 py-3 text-indigo-600 hover:text-indigo-500" wire:click="$toggle('showFilters')">--}}
{{--                                                @if ($showFilters) Hide @endif Advanced Search--}}
{{--                                            </x-button.link>--}}
                                        </div>
{{--                                        <div class="flex justify-between space-x-2">--}}
{{--                                            <div>--}}
{{--                                                @if($selectPage || $selected)--}}
{{--                                                    <div>--}}
{{--                                                        <x-jet-button wire:click="exportSelected" class="hover:shadow">--}}
{{--                                                            Download CSV--}}
{{--                                                        </x-jet-button>--}}
{{--                                                    </div>--}}
{{--                                                @else--}}

{{--                                                    <x-jet-button wire:click="exportReport" class="hover:shadow">--}}
{{--                                                        Download CSV--}}
{{--                                                    </x-jet-button>--}}
{{--                                                @endif--}}
{{--                                            </div>--}}
{{--                                        </div>--}}
                                    </div>
{{--                                    <div>--}}
{{--                                        @if ($showFilters)--}}
{{--                                            <div class="relative flex p-4 bg-white rounded">--}}
{{--                                                <div class="w-1/2 pr-2 space-y-4">--}}
{{--                                                    <x-input.group inline for="filter-status" label="Solution">--}}
{{--                                                        <x-input.select wire:key="filter.solution_type-0" wire:model="filter.solution_type" id="filter-status">--}}
{{--                                                            <option value="" disabled>Select Solution</option>--}}
{{--                                                            @foreach (App\Models\Reports::SOLUTION as $value => $label)--}}
{{--                                                                <option value="{{ $value }}">{{ $label }}</option>--}}
{{--                                                            @endforeach--}}
{{--                                                        </x-input.select>--}}
{{--                                                    </x-input.group>--}}
{{--                                                </div>--}}
{{--                                                <div class="w-1/2 pr-2 space-y-4">--}}
{{--                                                    <x-input.group inline for="filter-status" label="Severity">--}}
{{--                                                        <x-input.select wire:key="severityOrder-0" wire:model="sortDirection" id="filter-status">--}}
{{--                                                            <option value="desc">Descending</option>--}}
{{--                                                            <option value="asc">Ascending</option>--}}
{{--                                                        </x-input.select>--}}
{{--                                                    </x-input.group>--}}
{{--                                                </div>--}}
{{--                                            </div>--}}
{{--                                            <div class="relative flex p-1 bg-white rounded mr-3 mt-8">--}}
{{--                                                <div class="w-1/2 pl-2 space-y-4">--}}
{{--                                                    <x-button.link wire:click="resetFilters" class="absolute bottom-0 right-0 p-4 text-indigo-500 hover:text-indigo-600">Reset Filters</x-button.link>--}}
{{--                                                </div>--}}
{{--                                            </div>--}}

{{--                                        @endif--}}
{{--                                    </div>--}}
                                    <div class="bg-white py-2">
                                        <div class="flex-col mx-2 mt-1 space-y-4">
                                            <x-table class="table-auto max-w-3xl">
                                                <x-slot name="head">
{{--                                                    <x-table.heading class="w-6 pr-0">--}}
{{--                                                        <x-input.checkbox wire:model="selectPage" class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"/>--}}
{{--                                                    </x-table.heading>--}}
                                                    <x-table.heading sortable wire:click="sortBy('cvss_base')" :direction="$sortField === 'cvss_base' ? $sortDirection : null">Severity</x-table.heading>
                                                    <x-table.heading sortable wire:click="sortBy('name')" :direction="$sortField === 'name' ? $sortDirection : null">Name</x-table.heading>
                                                    <x-table.heading sortable wire:click="sortBy('family')" :direction="$sortField === 'Solution' ? $sortDirection : null">Family</x-table.heading>
                                                    <x-table.heading sortable wire:click="sortBy('creation_time')" :direction="$sortField === 'Category' ? $sortDirection : null">Creation Time</x-table.heading>
                                                    <x-table.heading sortable wire:click="sortBy('modification_time')" :direction="$sortField === 'Port' ? $sortDirection : null">Modification Time</x-table.heading>
                                                </x-slot>
                                                <x-slot name="body">
{{--                                                    <div>--}}
{{--                                                        @if($selectPage || $selected)--}}
{{--                                                            <x-table.row class="bg-indigo-50" wire:key="row-message">--}}
{{--                                                                <x-table.cell colspan="100%">--}}
{{--                                                                    @unless($selectAll)--}}
{{--                                                                        <div>--}}
{{--                                                                            <span>You have selected <strong>{{ count($selected) }}</strong> result, do you want select all <strong>{{ $reportsInfo->total() }}</strong>?</span>--}}
{{--                                                                            <x-button.link wire:click="selectAll" class="ml-1 text-blue-500">Select All</x-button.link>--}}
{{--                                                                        </div>--}}
{{--                                                                    @else--}}
{{--                                                                        <div>--}}
{{--                                                                            <span>You have selected all <strong>{{ $reportsInfo->total() }}</strong> results. <x-button.link wire:click="unSelectAll" class="ml-1 text-blue-500">UnSelect All</x-button.link></span>--}}
{{--                                                                        </div>--}}
{{--                                                                    @endif--}}
{{--                                                                </x-table.cell>--}}
{{--                                                            </x-table.row>--}}
{{--                                                        @endif--}}
{{--                                                    </div>--}}
                                                    <div>
                                                        @if($kb->count() > 0)
                                                            @foreach($kb as $knowledgebase)
                                                                <x-table.row wire:loading.delay.class="opacity-50" wire:target="search">
{{--                                                                    <x-table.cell class="pr-0">--}}
{{--                                                                        <div>--}}
{{--                                                                            <input wire:model="selected" wire:key="{{ $loop->index }}" value="{{ $knowledgebase->id }}" id="tasks" aria-describedby="tasks-id" name="tasks" type="checkbox" class="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500">--}}
{{--                                                                        </div>--}}
{{--                                                                    </x-table.cell>--}}
                                                                    <x-table.cell>
                                                                        <div wire:key="{{ $loop->index }}" class="flex items-center space-x-3">
                                                                            @if($knowledgebase->cvss_base >= '9.0')
                                                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-red-800 text-red-50 md:mt-2 lg:mt-0">
                                                                                    Critical
                                                                                </div>
                                                                            @elseif($knowledgebase->cvss_base >= '7.0' && $knowledgebase->cvss_base < '8.9')
                                                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-red-100 text-red-800 md:mt-2 lg:mt-0">
                                                                                    High
                                                                                </div>
                                                                            @elseif($knowledgebase->cvss_base >= '4.0' && $knowledgebase->cvss_base <= '6.9')
                                                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-yellow-100 text-yellow-700 md:mt-2 lg:mt-0">
                                                                                    Medium
                                                                                </div>
                                                                            @elseif($knowledgebase->cvss_base >= '0.1' && $knowledgebase->cvss_base <= '3.9')
                                                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-700 md:mt-2 lg:mt-0">
                                                                                    Low
                                                                                </div>
                                                                            @elseif($knowledgebase->cvss_base < '0.1')
                                                                                <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-blue-100 text-blue-700 md:mt-2 lg:mt-0">
                                                                                    Log
                                                                                </div>
                                                                            @else
                                                                                {{ $knowledgebase->cvss_base }}
                                                                            @endif
                                                                        </div>
                                                                    </x-table.cell>
                                                                    <x-table.cell>
                                                                        <div wire:key="{{ $loop->index }}">
                                                                            <x-button.link wire:click="kbDetails('{{$knowledgebase->uuid}}')" class="font-semibold text-gray-600 hover:underline hover:text-blue-600">{{ $knowledgebase->name }}</x-button.link>
                                                                        </div>
                                                                    </x-table.cell>
                                                                    <x-table.cell>
                                                                        <div wire:key="{{ $loop->index }}">
                                                                            {{ $knowledgebase->family }}
                                                                        </div>
                                                                    </x-table.cell>
                                                                    <x-table.cell>
                                                                        <div wire:key="{{ $loop->index }}">
                                                                            <span>{{ $knowledgebase->creation_time }}</span>
                                                                        </div>
                                                                    </x-table.cell>
                                                                    <x-table.cell>
                                                                        <div wire:key="{{ $loop->index }}">
                                                                            <span>{{ $knowledgebase->modification_time }}</span>
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
                                                        No results found.
                                                    </span>
                                                        </x-table.cell>
                                                    </x-table.row>
                                                    @endif
                                                </x-slot>
                                            </x-table>
                                            {{ $kb->links() }}
                                        </div>
                                    </div>
                                </div>
                            </div>
                    </section>
                </div>

{{--                <section aria-labelledby="timeline-title" class="lg:col-start-3 lg:col-span-1">--}}
{{--                    <!-- This example requires Tailwind CSS v2.0+ -->--}}
{{--                    <div class="bg-white shadow overflow-hidden sm:rounded-lg">--}}
{{--                        <div class="px-4 sm:px-6" style="padding-bottom: 0.80rem; padding-top: 0.75rem;">--}}
{{--                            <h3 class="text-lg leading-6 mt-1 font-medium text-gray-900">--}}
{{--                                Details--}}
{{--                            </h3>--}}
{{--                        </div>--}}
{{--                        <div class="border-t border-gray-200 px-4 py-5 sm:p-0">--}}
{{--                            <dl class="sm:divide-y sm:divide-gray-200">--}}
{{--                                <div wire:key="scanName-0" class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">--}}
{{--                                    <dt class="text-sm font-medium text-gray-500">--}}
{{--                                        Name--}}
{{--                                    </dt>--}}
{{--                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">--}}
{{--                                        {{ $scanDetails->scanName }}--}}
{{--                                    </dd>--}}
{{--                                </div>--}}
{{--                                <div wire:key="scanDescription-0" class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">--}}
{{--                                    <dt class="text-sm font-medium text-gray-500">--}}
{{--                                        Description--}}
{{--                                    </dt>--}}
{{--                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">--}}
{{--                                        {{ $scanDetails->scanDescription }}--}}
{{--                                    </dd>--}}
{{--                                </div>--}}
{{--                                <div wire:key="scanRunStatus-0" class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">--}}
{{--                                    <dt class="text-sm font-medium text-gray-500">--}}
{{--                                        Status--}}
{{--                                    </dt>--}}
{{--                                    @if(isset($scanDetails->run_status))--}}
{{--                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">--}}
{{--                                            @if($scanDetails->run_status == 0 || $scanDetails->run_status == 14)--}}
{{--                                                <span class="text-sm">--}}
{{--                                            Delete Requested--}}
{{--                                        </span>--}}
{{--                                            @elseif($scanDetails->run_status == 1)--}}
{{--                                                <div class="flex space-x-1">--}}
{{--                                        <span class="inline-flex px-2 text-xs font-semibold leading-5 text-white bg-green-700 rounded-full">--}}
{{--                                              Completed--}}
{{--                                          </span>--}}
{{--                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 text-green-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">--}}
{{--                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />--}}
{{--                                                    </svg>--}}
{{--                                                </div>--}}
{{--                                            @elseif($scanDetails->run_status == 2)--}}
{{--                                                <span class="inline-flex px-2 text-xs font-semibold leading-5 text-white bg-indigo-700 rounded-full">--}}
{{--                                          New--}}
{{--                                        </span>--}}
{{--                                            @elseif($scanDetails->run_status == 3)--}}
{{--                                                <span class="inline-flex px-2 text-xs font-semibold leading-5 text-yellow-800 bg-yellow-300 rounded-full">--}}
{{--                                          Requested--}}
{{--                                        </span>--}}
{{--                                            @elseif($scanDetails->run_status == 4)--}}
{{--                                                <div class="flex space-x-1">--}}
{{--                                            <span class="mt-1 inline-flex px-2 text-xs font-semibold leading-5 text-green-800 bg-green-200 rounded-full">--}}
{{--                                              Running--}}
{{--                                          </span>--}}

{{--                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mt-1 animate-spin text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">--}}
{{--                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />--}}
{{--                                                    </svg>--}}
{{--                                                </div>--}}
{{--                                            @elseif($scanDetails->run_status == 10)--}}
{{--                                                <span class="inline-flex px-2 text-xs font-semibold leading-5 text-yellow-800 bg-yellow-200 rounded-full">--}}
{{--                                          Stop Requested--}}
{{--                                        </span>--}}
{{--                                            @elseif($scanDetails->run_status == 11)--}}
{{--                                                <span class="inline-flex px-2 text-xs font-semibold leading-5 text-white bg-yellow-600 rounded-full">--}}
{{--                                          Stop Waiting--}}
{{--                                        </span>--}}
{{--                                            @elseif($scanDetails->run_status == 12)--}}
{{--                                                <span class="inline-flex px-2 text-xs font-semibold leading-5 text-red-800 bg-red-100 rounded-full">--}}
{{--                                          Stopped--}}
{{--                                        </span>--}}
{{--                                            @elseif($scanDetails->run_status == 13)--}}
{{--                                                <span class="inline-flex px-2 text-xs font-semibold leading-5 text-white bg-red-800 rounded-full">--}}
{{--                                          Interrupted--}}
{{--                                        </span>--}}
{{--                                            @elseif($scanDetails->run_status == 15)--}}
{{--                                                <span class="inline-flex px-2 text-xs font-semibold leading-5 text-white bg-gray-800 rounded-full">--}}
{{--                                          Stop Requested Error--}}
{{--                                        </span>--}}
{{--                                            @elseif($scanDetails->run_status == 16 || $scanDetails->run_status == 17)--}}
{{--                                                <span class="inline-flex px-2 text-xs font-semibold leading-5 text-white bg-yellow-300 rounded-full">--}}
{{--                                          Delete Waiting--}}
{{--                                        </span>--}}
{{--                                            @endif--}}
{{--                                        </dd>--}}
{{--                                    @else--}}
{{--                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">--}}
{{--                                            Loading ...--}}
{{--                                        </dd>--}}
{{--                                    @endif--}}
{{--                                </div>--}}
{{--                                @if($scanDetails->run_status != 3)--}}
{{--                                    <div wire:key="timeStart-0" class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">--}}
{{--                                        <dt class="text-sm font-medium text-gray-500">--}}
{{--                                            Start--}}
{{--                                        </dt>--}}
{{--                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">--}}
{{--                                            {{ $scanDetails->start_time->diffForHumans() }}--}}
{{--                                        </dd>--}}
{{--                                    </div>--}}
{{--                                @endif--}}
{{--                                @if($scanDetails->run_status == 1)--}}
{{--                                    <div wire:key="endTime-0" class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">--}}
{{--                                        <dt class="text-sm font-medium text-gray-500">--}}
{{--                                            End--}}
{{--                                        </dt>--}}
{{--                                        <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">--}}
{{--                                            {{ $scanDetails->end_time->diffForHumans() }}--}}
{{--                                        </dd>--}}
{{--                                    </div>--}}
{{--                                @endif--}}
{{--                                <div wire:key="creationTime-0" class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">--}}
{{--                                    <dt class="text-sm font-medium text-gray-500">--}}
{{--                                        Created--}}
{{--                                    </dt>--}}
{{--                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">--}}
{{--                                        {{ $scanDetails->creation_time->diffForHumans() }}--}}
{{--                                    </dd>--}}
{{--                                </div>--}}
{{--                                <div wire:key="schedule-0" class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">--}}
{{--                                    <dt class="text-sm font-medium text-gray-500">--}}
{{--                                        Scheduled--}}
{{--                                    </dt>--}}
{{--                                    <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">--}}
{{--                                        @if($scanDetails->schedule == 0)--}}
{{--                                            {{ 'No' }}--}}
{{--                                        @else--}}
{{--                                            {{ 'Yes' }}--}}
{{--                                        @endif--}}
{{--                                    </dd>--}}
{{--                                </div>--}}
{{--                            </dl>--}}
{{--                        </div>--}}
{{--                    </div>--}}
{{--                </section>--}}
            </div>
        </main>
    </div>
</div>
