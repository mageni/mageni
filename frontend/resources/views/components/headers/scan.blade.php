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
        </ol>
    </nav>
</x-slot>
