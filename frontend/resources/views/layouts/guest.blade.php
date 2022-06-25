<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="csrf-token" content="{{ csrf_token() }}">

        <title>{{ config('app.name', 'Laravel') }}</title>

        <!-- Fonts -->
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700&display=swap">

        <!-- Styles -->
        <script src="{{ url('js/tailwind.js') }}"></script>
        <script>
            tailwind.config = {
                theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        serif: ['Inter', 'serif'],
                        }
                    }
                }
            }
        </script>

        <!-- Scripts -->
        <script src="{{ mix('js/app.js') }}" defer></script>
    </head>
    <body>
    @if(env('APP_ENV') === 'demo')
    <div class="relative bg-indigo-600">
        <div class="px-3 py-3 mx-auto max-w-7xl sm:px-6 lg:px-8">
        <div class="pr-16 sm:text-center sm:px-16">
            <p class="font-medium text-white">
            <span class="md:hidden"> We announced a new product! </span>
            <span class="hidden md:inline"> Welcome to the Live Demo! The username is <span class="font-extrabold">demo@mageni.net</span> and the password is <span class="font-extrabold">demo</span> </span>
            {{-- <span class="block sm:ml-2 sm:inline-block">
                <a href="#" class="font-bold text-white underline"> Learn more <span aria-hidden="true">&rarr;</span></a>
            </span> --}}
            </p>
        </div>
        <div class="absolute inset-y-0 right-0 flex items-start pt-1 pr-1 sm:pt-1 sm:pr-2 sm:items-start">
            <button type="button" class="flex p-2 rounded-md hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-white">
            <span class="sr-only">Dismiss</span>
            <!-- Heroicon name: outline/x -->
            <svg class="w-6 h-6 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
            </button>
        </div>
        </div>
    </div>
    @endif
  
    <div class="font-sans antialiased text-gray-900">
        {{ $slot }}
    </div>
    </body>
</html>
