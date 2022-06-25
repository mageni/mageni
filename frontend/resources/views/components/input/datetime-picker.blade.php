@props([
    'options' => "{dateFormat:'m/d/Y H:i', altFormat:'m/d/Y H:i', minDate: 'today', altInput:true, enableTime:true }",
])

<div wire:ignore>
    <input 
        x-data 
        x-init="flatpickr($refs.input, {{ $options }} );" 
        x-ref="input" 
        type="text" 
        class="block border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 w-80 sm:text-sm" 
        data-input
        {{ $attributes }} 
    />
</div>
