<div wire:poll.keep-alive>
    <div class="grid gap-6 mb-8 md:grid-cols-2 xl:grid-cols-4">
        <!-- Card -->
        <div class="flex items-center p-4 bg-white hover:bg-blue-50 hover:border-transparent hover:shadow-lg rounded-lg border border-gray-100 shadow-xs shadow">
            <div class="p-3 mr-4 text-blue-500 bg-blue-100 rounded-full dark:text-orange-100 dark:bg-orange-500">
                <i class="fas fa-eye"></i>
            </div>
            <div>
                <p class="mb-2 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Scans
                </p>
                <p class="text-lg font-semibold text-gray-700 dark:text-gray-200">
                    {{ $scans }}
                </p>
            </div>
        </div>
        <!-- Card -->
        <div class="flex items-center p-4 bg-white hover:bg-blue-50 hover:border-transparent hover:shadow-lg rounded-lg border border-gray-100 shadow-xs shadow">
            <div class="p-3 mr-4 text-green-500 bg-green-100 rounded-full dark:text-green-100 dark:bg-green-500">
                <i class="fas fa-thumbs-up"></i>
            </div>
            <div>
                <p class="mb-2 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Completed
                </p>
                <p class="text-lg font-semibold text-gray-700 dark:text-gray-200">
                    1
                </p>
            </div>
        </div>
        <!-- Card -->
        <div class="flex items-center p-4 bg-white hover:bg-blue-50 hover:border-transparent hover:shadow-lg rounded-lg border border-gray-100 shadow-xs shadow">
            <div class="p-3 mr-4 text-blue-500 bg-blue-100 rounded-full dark:text-blue-100 dark:bg-blue-500">
                <i class="fas fa-power-off"></i>
            </div>
            <div>
                <p class="mb-2 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Stopped
                </p>
                <p class="text-lg font-semibold text-gray-700 dark:text-gray-200">
                    9
                </p>
            </div>
        </div>
        <!-- Card -->
        <div class="flex items-center p-4 bg-white hover:bg-blue-50 hover:border-transparent hover:shadow-lg rounded-lg border border-gray-100 shadow-xs shadow">
            <div class="p-3 mr-4 text-teal-500 bg-teal-100 rounded-full dark:text-teal-100 dark:bg-teal-500">
                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M18 5v8a2 2 0 01-2 2h-5l-5 4v-4H4a2 2 0 01-2-2V5a2 2 0 012-2h12a2 2 0 012 2zM7 8H5v2h2V8zm2 0h2v2H9V8zm6 0h-2v2h2V8z" clip-rule="evenodd"></path>
                </svg>
            </div>
            <div>
                <p class="mb-2 text-sm font-medium text-gray-600 dark:text-gray-400">
                    Interrupted
                </p>
                <p class="text-lg font-semibold text-gray-700 dark:text-gray-200">
                    0
                </p>
            </div>
        </div>
    </div>
</div>




