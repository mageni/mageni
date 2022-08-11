<span
    {{ $attributes->merge([
        'class' => 'text-sm leading-5 font-medium cursor-pointer focus:outline-none transition duration-150 ease-in-out' . ($attributes->get('disabled') ? ' opacity-75 cursor-not-allowed' : ''),
    ]) }}
>
    {{ $slot }}
</span>
