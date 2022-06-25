@props([
    'data' => null,
])

<x-slot name="header">
    <nav class="flex max-w-full" aria-label="Breadcrumb">
        <ol class="flex items-center space-x-4">
            <li>
                <div class="flex items-center">
                    <a href="{{ url('scan') }}" class="text-sm font-medium text-gray-500 hover:text-gray-700" aria-current="page">
                        My Scans
                    </a>
                </div>
            </li>
            <li>
                <div class="flex items-center">
                    <!-- Heroicon name: solid/chevron-right -->
                    <svg class="flex-shrink-0 h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clip-rule="evenodd" />
                    </svg>
                    <a href="#" class="ml-4 text-sm font-medium text-gray-500 hover:text-gray-700" aria-current="page">
                        @if(isset($data))
                            {{ $data }}
                        @else
                            My Reports
                        @endif
                    </a>
                </div>
            </li>
        </ol>
    </nav>
</x-slot>
