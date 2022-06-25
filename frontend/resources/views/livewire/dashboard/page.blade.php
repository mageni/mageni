<div>
    <x-headers.dashboard />
    {{-- {{ dd($vulnDec)}} --}}
    <main class="py-10">
        {{-- {{ var_dump($avgcvss[0]->avgseverity) }} --}}
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
                            Upgrade your account to remove this message, unlock more features like notifications, schedules, manage users, and have access to support
                        </a>
                    </p>
                </div>
                </div>
            </div>
            @endif

            <div>
                {{-- <h3 class="text-lg leading-6 font-medium text-gray-900">Last 30 days</h3> --}}
                <dl class="mt-1 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
                    <div class="relative bg-white pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">
                        <dt>
                            <div class="absolute bg-indigo-500 rounded-md p-3">
                                <!-- Heroicon name: outline/users -->
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01" />
                                </svg>
                            </div>
                            <p class="ml-16 text-sm font-medium text-gray-500 truncate">Total Vulnerabilities</p>
                        </dt>
                        <dd class="ml-16 pb-6 flex items-baseline sm:pb-7">
                            <p class="text-2xl font-semibold text-gray-900">{{ number_format($allvuln) }}</p>
                            {{-- <p class="ml-2 flex items-baseline text-sm font-semibold text-green-600">
                                <!-- Heroicon name: solid/arrow-sm-up -->
                                <svg class="self-center flex-shrink-0 h-5 w-5 text-green-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                <path fill-rule="evenodd" d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z" clip-rule="evenodd" />
                                </svg>
                                <span class="sr-only"> Increased by </span>
                                122
                            </p> --}}
                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">
                                <div class="text-sm">
                                <a href="{{ route('vulnerabilities') }}" class="font-medium text-indigo-600 hover:text-indigo-500"> View all<span class="sr-only"> Total Vulnerabilities stats</span></a>
                                </div>
                            </div>
                        </dd>
                    </div>
                
                    <div class="relative bg-white pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">
                        <dt>
                            <div class="absolute bg-indigo-500 rounded-md p-3">
                                <!-- Heroicon name: outline/mail-open -->
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                                  </svg>
                            </div>
                            <p class="ml-16 text-sm font-medium text-gray-500 truncate">Total Assets</p>
                        </dt>
                        <dd class="ml-16 pb-6 flex items-baseline sm:pb-7">
                            <p class="text-2xl font-semibold text-gray-900">{{ number_format($allAssets) }}</p>
                            {{-- <p class="ml-2 flex items-baseline text-sm font-semibold text-green-600">
                                <!-- Heroicon name: solid/arrow-sm-up -->
                                <svg class="self-center flex-shrink-0 h-5 w-5 text-green-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                <path fill-rule="evenodd" d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z" clip-rule="evenodd" />
                                </svg>
                                <span class="sr-only"> Increased by </span>
                                5.4%
                            </p> --}}
                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">
                                <div class="text-sm">
                                <a 
                                href="#" 
                                x-data
                                x-tooltip="Coming soon"
                                class="font-medium cursor-not-allowed text-indigo-600 hover:text-indigo-500"> 
                                    View all<span class="sr-only"> Assets</span>
                                </a>
                                </div>
                            </div>
                        </dd>
                    </div>
                
                    <div class="relative bg-white pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">
                        <dt>
                            <div class="absolute bg-indigo-500 rounded-md p-3">
                                <!-- Heroicon name: outline/cursor-click -->
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                </svg>
                            </div>
                            <p class="ml-16 text-sm font-medium text-gray-500 truncate">Total Scans</p>
                        </dt>
                        <dd class="ml-16 pb-6 flex items-baseline sm:pb-7">
                            <p class="text-2xl font-semibold text-gray-900">{{ number_format($scansAll) }}</p>
                            {{-- <p class="ml-2 flex items-baseline text-sm font-semibold text-red-600">
                                <!-- Heroicon name: solid/arrow-sm-down -->
                                <svg class="self-center flex-shrink-0 h-5 w-5 text-red-500" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                <path fill-rule="evenodd" d="M14.707 10.293a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 12.586V5a1 1 0 012 0v7.586l2.293-2.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                                </svg>
                                <span class="sr-only"> Decreased by </span>
                                3.2%
                            </p> --}}
                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">
                                <div class="text-sm">
                                <a href="{{ route('scans') }}" class="font-medium text-indigo-600 hover:text-indigo-500"> View all<span class="sr-only"> Total Scans</span></a>
                                </div>
                            </div>
                        </dd>
                    </div>
                </dl>
            </div>

            <div>
                {{-- <h3 class="mt-5 text-lg leading-6 font-medium text-gray-900">Last 30 days</h3> --}}
                <dl class="mt-10 grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-3">
                    <div class="relative h-96 bg-white py-2 pb-12 px-4 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">
                        <dd class="ml-24 py-8 flex items-baseline sm:pb-7">
                            <div id="piechart_3d" class="absolute inset-0 mb-8 h-auto"></div>
                            {{-- <div id="chart">  --}}
                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">
                                <div class="text-sm">
                                <span class="font-medium text-indigo-600 hover:text-indigo-500"> Vulnerabilities by Severity<span class="sr-only"> Vulnerabilities by Severity</span></span>
                                </div>
                            </div>
                        </dd>
                    </div>
                
                    <div class="relative h-96 bg-white py-2 pb-12 px-4 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden">
                        <dd class="ml-24 py-8 flex items-baseline sm:pb-7">
                            <div id="piechart" class="absolute inset-0 mb-8 h-auto"></div>
                            {{-- <div id="chart">  --}}
                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">
                                <div class="text-sm">
                                <span class="font-medium text-indigo-600 hover:text-indigo-500"> Scans by Status<span class="sr-only"> Scans by Status</span></span>
                                </div>
                            </div>
                        </dd>
                    </div>

                    <div class="relative h-96 bg-white py-2 pb-12 px-4 sm:pt-1 sm:px-6 shadow rounded-lg overflow-hidden">
                        <dd class="py-8 flex items-baseline sm:pb-7">
                            <ul class="list-disc ml-4">
                                @foreach($top10Critical as $top)
                                    <li wire:click="top10Details('{{$top->oid}}')" class="pb-1 cursor-pointer text-gray-600 text-base hover:text-indigo-500">
                                        {{ $top->name }}
                                    </li>
                                @endforeach
                            </ul>
                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">
                                <div class="text-sm">
                                <span class="font-medium text-indigo-600 hover:text-indigo-500"> Top Critical Vulnerabilities<span class="sr-only"> Top Critical Vulnerabilities</span></span>
                                </div>
                            </div>
                        </dd>
                    </div>
                </dl>
            </div>

            <div>
                {{-- <h3 class="mt-5 text-lg leading-6 font-medium text-gray-900">Last 30 days</h3> --}}
                <dl class="mt-10 grid grid-cols-1 gap-5 sm:grid-cols-1 lg:grid-cols-1">

                    <div class="relative bg-white py-2 pb-12 px-4 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden" style="height: 28rem;">
                        <dd class="ml-24 py-8 flex items-baseline sm:pb-7">
                            <div id="curve_chart" class="absolute inset-0 mb-8 h-auto"></div>
                            {{-- <div id="chart">  --}}
                            <div class="absolute bottom-0 inset-x-0 bg-gray-50 px-4 py-4 sm:px-6">
                                <div class="text-sm">
                                <span class="font-medium text-indigo-600 hover:text-indigo-500"> Vulnerabilities by Month<span class="sr-only"> Vulnerabilities by Month</span></span>
                                </div>
                            </div>
                        </dd>
                    </div>
                </dl>
            </div>

            {{-- <div id="chart"> --}}

        </div>
    </main>
</div>
@push('apexcharts')
<script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
@endpush
@push('dashboard-charts')
<script type="text/javascript">
    google.charts.load("current", {packages:["corechart"]});
    google.charts.setOnLoadCallback(drawChart);
    function drawChart() {
      var data = google.visualization.arrayToDataTable([
        ['Vulnerabilities', 'Count'],
        ['Critical',        {{ $criticalvuln }}],
        ['High',            {{ $highvuln }}],
        ['Medium',          {{ $mediumvuln }}],
        ['Low',             {{ $lowvuln }}],
        ['Informational',   {{ $informational }}]
      ]);

      var options = {
        is3D: false,
        pieHole: 0.4,
        legend: 'none',
        colors: ['#f50057', '#ff1744', '#ffc400', '#64dd17', '#3d5afe']
      };

      var chart = new google.visualization.PieChart(document.getElementById('piechart_3d'));
      chart.draw(data, options);
    }
</script>
<script type="text/javascript">
    google.charts.load('current', {'packages':['corechart']});
    google.charts.setOnLoadCallback(drawChart);

    function drawChart() {

      var data = google.visualization.arrayToDataTable([
        ['Scans', 'Scans Created'],
        ['Total',     {{ $scansAll }}],
        ['Completed',      {{ $scansCompleted }}],
        ['New',  {{ $scansNew }}],
        ['Stopped', {{ $scansStopped }}],
        ['Running', {{ $scansRunning }}]
      ]);

      var options = {
        is3D: false,
        legend: 'none',
        colors: ['#3f51b5', '#5c6bc0', '#7986cb', '#9fa8da', '#c5cae9']
      };

      var chart = new google.visualization.PieChart(document.getElementById('piechart'));

      chart.draw(data, options);
    }
</script>
<script type="text/javascript">
    google.charts.load('current', {'packages':['corechart']});
    google.charts.setOnLoadCallback(drawChart);

    function drawChart() {
      var data = google.visualization.arrayToDataTable([
        ['Year', 'Vulnerabilities'],
        ['January',  {{ $vulnJan }}],
        ['February',  {{ $vulnFeb }}],
        ['March',  {{ $vulnMar }}],
        ['April',  {{ $vulnApr }}],
        ['May',  {{ $vulnMay }}],
        ['June',  {{ $vulnJun }}],
        ['July',  {{ $vulnJul }}],
        ['August',  {{ $vulnAug }}],
        ['September',  {{ $vulnSep }}],
        ['October',  {{ $vulnOct }}],
        ['November',  {{ $vulnNov }}],
        ['December',  {{ $vulnDec }}]
      ]);

      var options = {
        curveType: 'function',
        legend: 'none',
        colors: ['#3f51b5']
      };

      var chart = new google.visualization.LineChart(document.getElementById('curve_chart'));

      chart.draw(data, options);
    }
</script>
@endpush
