@if ($errors->any())
    <div {{ $attributes }}>
        <div class="mt-4 font-medium text-red-600">{{ __('Whoops! Something went wrong.') }}</div>

        <ul class="mt-3 list-disc list-inside text-sm text-red-600">
            @foreach ($errors->all() as $error)
                <li>{{ $error }}</li>
            @endforeach
        </ul>

        <ul class="mt-3 list-disc list-inside text-sm text-red-600">
            <li>Password lost? Contact Mageni's support.</li>
        </ul>
    </div>
@endif
