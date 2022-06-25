<div class="md:grid md:grid-cols-3 md:gap-6">
    <x-jet-section-title>
        <x-slot name="title">License</x-slot>
        <x-slot name="description">Set your license</x-slot>
    </x-jet-section-title>

    <div class="mt-5 md:mt-0 md:col-span-2">

      <div class="shadow sm:rounded-md sm:overflow-hidden">
        <div class="bg-white py-6 px-4 space-y-6 sm:p-6">
          <div>
            <h3 class="text-lg leading-6 font-medium text-gray-900">Plan</h3>
            <p class="mt-1 text-sm text-gray-500">
              @if($plan === 'Free')
                You are on the <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800"> Community </span> plan.
              @else
                You are on the <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800"> Paid </span> plan.
              @endif
            </p>
          </div>

          <div class="grid grid-cols-3 gap-6">
            <div class="col-span-3 sm:col-span-2">
              <label for="company-website" class="block text-sm font-medium text-gray-700"> License </label>
              <div class="mt-1 rounded-md shadow-sm flex">
                {{-- <span class="bg-gray-50 border border-r-0 border-gray-300 rounded-l-md px-3 inline-flex items-center text-gray-500 sm:text-sm"> workcation.com/ </span> --}}
                <input wire:model="license" type="text" name="username" id="username" autocomplete="username" class="focus:ring-indigo-500 focus:border-indigo-500 flex-grow block w-full min-w-0 rounded-none rounded-r-md sm:text-sm border-gray-300">
              </div>
              @if($errors->first('license'))
                  <div class="flex flex-row py-1 space-x-1">
                      <div class="flex-shrink-0">
                          <svg class="w-5 h-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                              <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                          </svg>
                      </div>
                      <p class="text-sm text-red-500">
                          {{ $errors->first('license') }}
                      </p>
                  </div>
              @endif
            </div>
          </div>
        </div>
        <div class="px-4 py-3 bg-gray-50 text-right sm:px-6">
          <button wire:click="setLicense" type="submit" class="bg-indigo-600 border border-transparent rounded-md shadow-sm py-2 px-4 inline-flex justify-center text-sm font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">Save</button>
        </div>
      </div>

    </div>
</div>

