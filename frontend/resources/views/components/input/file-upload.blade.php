<div wire:ignore
     x-data
     x-init="
        FilePond.setOptions({
            credits: false,
            server: {
                process:(fieldName, file, metadata, load, error, progress, abort, transfer, options) => {
                    @this.upload('sshKey', file, load, error, progress)
            },
            revert: (filename, load) => {
                @this.removeUpload('sshKey', filename, load)
            },
        },
        });

        FilePond.create($refs.input);
    ">
    {{ $slot }}
    <input {{ $attributes }} x-ref="input" type="file">
</div>
