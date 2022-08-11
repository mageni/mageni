<div>
    <x-headers.vulnerabilities />

    <main class="py-10" wire:poll.keep-alive>
        <div class="max-w-full mx-auto pr-4 sm:px-6 md:flex md:items-center md:justify-between md:space-x-5 lg:max-w-full lg:px-6">
            <div class="flex items-center space-x-5">
                <div>
                    <h1 class="text-2xl font-bold text-gray-900">{{ $details->name }}</h1>
                    <p class="text-sm font-medium text-gray-500">Found on <time datetime="2020-08-25">{{ $details->date }}</time></p>
                </div>
            </div>
        </div>

        <div class="mt-8 max-w-full mx-auto grid grid-cols-1 gap-6 sm:px-6 lg:max-w-full lg:grid-flow-col-dense lg:grid-cols-3">
            <div class="space-y-6 lg:col-start-1 lg:col-span-2">
                <!-- Description list-->

                @if(!empty($details->summary))
                    <section aria-labelledby="applicant-information-title">
                        <div class="bg-white shadow sm:rounded-lg">
                            <div class="px-4 py-5 sm:px-6">
                                <h2 id="applicant-information-title" class="text-lg leading-6 font-medium text-gray-900">
                                    Summary
                                </h2>
                                <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                    A brief statement about the vulnerability
                                </p>
                            </div>
                            <div class="border-t border-gray-200 px-4 py-5 sm:px-6">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-2">
                                        <dd class="mt-1 text-sm text-gray-900">
                                            {{ $details->summary }}
                                        </dd>
                                    </div>
                                </dl>
                            </div>
                        </div>
                    </section>
                @endif

                @if(!empty($details->impact))
                    <section aria-labelledby="applicant-information-title">
                        <div class="bg-white shadow sm:rounded-lg">
                            <div class="px-4 py-5 sm:px-6">
                                <h2 id="applicant-information-title" class="text-lg leading-6 font-medium text-gray-900">
                                    Impact
                                </h2>
                                <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                    The type of harm an attack could cause if the vulnerability were exploited.
                                </p>
                            </div>
                            <div class="border-t border-gray-200 px-4 py-5 sm:px-6">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-2">
                                        <dd class="mt-1 text-sm text-gray-900">
                                            {{ $details->impact }}
                                        </dd>
                                    </div>
                                </dl>
                            </div>
                        </div>
                    </section>
                @endif

                @if(!empty($details->insight))
                    <section aria-labelledby="applicant-information-title">
                        <div class="bg-white shadow sm:rounded-lg">
                            <div class="px-4 py-5 sm:px-6">
                                <h2 id="applicant-information-title" class="text-lg leading-6 font-medium text-gray-900">
                                    Insight
                                </h2>
                                <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                    To help you gain accurate and deep intuitive understanding of the vulnerability
                                </p>
                            </div>
                            <div class="border-t border-gray-200 px-4 py-5 sm:px-6">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-2">
                                        <dd class="mt-1 text-sm text-gray-900">
                                            {{ $details->insight }}
                                        </dd>
                                    </div>

                                </dl>
                            </div>
                        </div>
                    </section>
                @endif

                @if(!empty($details->affected))
                    <section aria-labelledby="applicant-information-title">
                        <div class="bg-white shadow sm:rounded-lg">
                            <div class="px-4 py-5 sm:px-6">
                                <h2 id="applicant-information-title" class="text-lg leading-6 font-medium text-gray-900">
                                    Affected
                                </h2>
                                <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                    Affected Systems
                                </p>
                            </div>
                            <div class="border-t border-gray-200 px-4 py-5 sm:px-6">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-2">
                                        <dd class="mt-1 text-sm text-gray-900">
                                            {{ $details->affected }}
                                        </dd>
                                    </div>

                                </dl>
                            </div>
                        </div>
                    </section>
                @endif

                <div>
                                    
                    <div class="mt-8 flex flex-col">
                    <div class="-my-2 -mx-4 overflow-x-auto sm:-mx-6 lg:-mx-8">
                        <div class="inline-block min-w-full py-2 align-middle md:px-6 lg:px-8">
                        <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
                            <table class="min-w-full">
                                <thead class="bg-white">
                                    <tr>
                                    <th colspan="2" scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">IP</th>
                                    <th colspan="3" scope="col" class="px-4 py-2 text-left text-sm font-semibold text-gray-900 sm:px-6">Hostname</th>
                                    <th colspan="3" scope="col" class="px-4 py-2 text-left text-sm font-semibold text-gray-900 sm:px-6">Port</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white">
                                    @foreach($hosts as $host)
                                    <tr class="border-t border-gray-200">
                                        <th colspan="2" scope="colgroup" class="bg-gray-50 px-4 py-2 text-left text-sm font-semibold text-gray-900 sm:px-6">{{ $host->host }}</th>
                                        <th colspan="3" scope="colgroup" class="bg-gray-50 px-4 py-2 text-left text-sm font-semibold text-gray-900 sm:px-6">{{ $host->hostname }}</th>
                                        <th colspan="1" scope="colgroup" class="bg-gray-50 px-4 py-2 text-left text-sm font-semibold text-gray-900 sm:px-6">{{ $host->port }}</th>
                                    </tr>
                                        @if(!empty($details->description))
                                        <tr class="border-t border-gray-300">
                                            <td colspan="6" class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                                                <dd class="mt-1 bg-text-sm text-gray-900 font-mono text-sm">
                                                    {!! nl2br(e($details->description)) !!}
                                                </dd>
                                            </td>
                                        </tr>
                                        @else
                                        <tr class="border-t border-gray-300">
                                            <td colspan="6" class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">
                                                <dd class="mt-1 bg-text-sm text-gray-900 font-mono text-sm">
                                                    {{ 'Did not yield an output' }}
                                                </dd>
                                            </td>
                                        </tr>
                                        @endif
                                    @endforeach
                    
                                  
                                </tbody>
                            </table>
                        </div>
                        </div>
                    </div>
                    </div>
                </div>

                @if(!empty($details->solution))
                    <section aria-labelledby="applicant-information-title">
                        <div class="bg-white shadow sm:rounded-lg">
                            <div class="px-4 py-5 sm:px-6">
                                <h2 id="applicant-information-title" class="text-lg leading-6 font-medium text-gray-900">
                                    Solution
                                </h2>
                                <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                    How to solve or mitigate the vulnerability
                                </p>
                            </div>
                            <div class="border-t border-gray-200 px-4 py-5 sm:px-6">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-2">
                                        <dd class="mt-1 text-sm text-gray-900">
                                            {{ $details->solution }}
                                        </dd>
                                    </div>

                                </dl>
                            </div>
                        </div>
                    </section>
                @endif

                @if(!empty($details->vuldetect))
                    <section aria-labelledby="applicant-information-title">
                        <div class="bg-white shadow sm:rounded-lg">
                            <div class="px-4 py-5 sm:px-6">
                                <h2 id="applicant-information-title" class="text-lg leading-6 font-medium text-gray-900">
                                    Detection
                                </h2>
                                <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                    How the vulnerability was detected
                                </p>
                            </div>
                            <div class="border-t border-gray-200 px-4 py-5 sm:px-6">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-2">
                                        <dd class="mt-1 text-sm text-gray-900">
                                            {{ $details->vuldetect }}
                                        </dd>
                                    </div>
                                </dl>
                            </div>
                        </div>
                    </section>
                @endif


            @if($details->cve != 'NOCVE')
                    <section aria-labelledby="applicant-information-title">
                        <div class="bg-white shadow sm:rounded-lg">
                            <div class="px-4 py-5 sm:px-6">
                                <h2 id="applicant-information-title" class="text-lg leading-6 font-medium text-gray-900">
                                    CVE
                                </h2>
                                <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                    Common Vulnerabilities and Exposures
                                </p>
                            </div>
                            <div class="border-t border-gray-200 px-4 py-5 sm:px-6">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-1">
                                        <dd class="mt-1 text-sm text-gray-900">
                                           <ul>
                                               @foreach(explode(",", $details->cve) as $cvelist)
                                               @php
                                                   $cve = trim($cvelist)
                                               @endphp
                                               <li><a href="https://nvd.nist.gov/vuln/detail/{{ $cve }}" title="{{ $cve }}" target="_blank" rel="noopener noreferrer">{{ $cve }}</a></li>
                                               @endforeach
                                           </ul>
                                        </dd>
                                    </div>
                                </dl>
                            </div>
                        </div>
                    </section>
                @endif

                @if($details->xref != 'NOXREF')
                    <section aria-labelledby="applicant-information-title">
                        <div class="bg-white shadow sm:rounded-lg">
                            <div class="px-4 py-5 sm:px-6">
                                <h2 id="applicant-information-title" class="text-lg leading-6 font-medium text-gray-900">
                                    References
                                </h2>
                                <p class="mt-1 max-w-2xl text-sm text-gray-500">
                                    Source of information in order to ascertain the vulnerability
                                </p>
                            </div>
                            <div class="border-t border-gray-200 px-4 py-5 sm:px-6">
                                <dl class="grid grid-cols-1 gap-x-4 gap-y-8 sm:grid-cols-2">
                                    <div class="sm:col-span-2">
                                        <dd class="mt-1 text-sm text-gray-900">
                                           <ul>
                                               @foreach(explode(",", $details->xref) as $reflist)
                                                   @php
                                                       $regexurl = '/(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/';
                                                       preg_match($regexurl, $reflist, $matches, PREG_UNMATCHED_AS_NULL);
                                                       $url= @$matches[0];
                                                   @endphp
                                               <li><a href="{{ $url }}" target="_blank" rel="noopener noreferrer" title="{{ $url }}">{{ $url }}</a></li>
                                               @endforeach
                                           </ul>
                                        </dd>
                                    </div>
                                </dl>
                            </div>
                        </div>
                    </section>
                @endif

            </div>

            <section aria-labelledby="timeline-title" class="lg:col-start-3 lg:col-span-1">
                <!-- This example requires Tailwind CSS v2.0+ -->
                <div class="bg-white shadow overflow-hidden sm:rounded-lg">
                    <div class="px-4 py-5 sm:px-6">
                        <h3 class="text-lg leading-6 font-medium text-gray-900">Vulnerability Information</h3>
                        <p class="mt-1 max-w-2xl text-sm text-gray-500">CVE details and analysis.</p>
                    </div>
                    <div class="border-t border-gray-200 px-4 py-5 sm:p-0">
                        <dl class="sm:divide-y sm:divide-gray-200">
                            <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                                <dt class="text-sm font-medium text-gray-500">Severity</dt>
                                <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                                    @if($details->cvss_base >= '9.0')
                                        <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-red-800 text-red-50 md:mt-2 lg:mt-0">
                                            Critical
                                        </div>
                                    @elseif($details->cvss_base >= '7.0' && $details->cvss_base < '8.9')
                                        <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-red-100 text-red-800 md:mt-2 lg:mt-0">
                                            High
                                        </div>
                                    @elseif($details->cvss_base >= '4.0' && $details->cvss_base <= '6.9')
                                        <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-yellow-100 text-yellow-700 md:mt-2 lg:mt-0">
                                            Medium
                                        </div>
                                    @elseif($details->cvss_base >= '0.1' && $details->cvss_base <= '3.9')
                                        <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-green-100 text-green-700 md:mt-2 lg:mt-0">
                                            Low
                                        </div>
                                    @elseif($details->cvss_base < '0.1')
                                        <div class="inline-flex items-baseline px-2.5 py-0.5 rounded-full text-sm font-medium bg-blue-100 text-blue-700 md:mt-2 lg:mt-0">
                                            Log
                                        </div>
                                    @else
                                        {{ $details->CVSS }}
                                    @endif
                                </dd>
                            </div>
                            <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                                <dt class="text-sm font-medium text-gray-500">CVSSv2 Score</dt>
                                <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ $details->cvss_base }}</dd>
                            </div>
                            <div class="py-4 sm:py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                                <dt class="text-sm font-medium text-gray-500">CVSSv2 Base</dt>
                                <dd class="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">{{ $details->cvssv2_base_vector }}</dd>
                            </div>
                        </dl>
                    </div>
                </div>
            </section>
        </div>
    </main>
</div>
