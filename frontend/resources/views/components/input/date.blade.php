<div
    x-data="{ value: @entangle($attributes->wire('model')), picker: undefined }"
    x-init="new Pikaday({ field: $refs.input, format: 'MM/DD/YYYY', onOpen() { this.setDate($refs.input.value) } })"
    x-on:change="value = $event.target.value"
    class="flex rounded-md shadow-sm"
>
    <input
        {{ $attributes->whereDoesntStartWith('wire:model') }}
        x-ref="input"
        x-bind:value="value"
        class="rounded-md flex-1 form-input block w-full mt-1 block transition duration-150 ease-in-out sm:text-sm sm:leading-5"
    />
</div>
