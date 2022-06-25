<script>
    function select(config) {
        return {
            data: config.data,

            emptyOptionsMessage: config.emptyOptionsMessage ?? 'No results match your search.',

            focusedOptionIndex: null,

            name: config.name,

            open: false,

            options: {},

            placeholder: config.placeholder ?? 'Select an option',

            search: '',

            value: config.value,

            closeListbox: function () {
                this.open = false

                this.focusedOptionIndex = null

                this.search = ''
            },

            focusNextOption: function () {
                if (this.focusedOptionIndex === null) return this.focusedOptionIndex = Object.keys(this.options).length - 1

                if (this.focusedOptionIndex + 1 >= Object.keys(this.options).length) return

                this.focusedOptionIndex++

                this.$refs.listbox.children[this.focusedOptionIndex].scrollIntoView({
                    block: "center",
                })
            },

            focusPreviousOption: function () {
                if (this.focusedOptionIndex === null) return this.focusedOptionIndex = 0

                if (this.focusedOptionIndex <= 0) return

                this.focusedOptionIndex--

                this.$refs.listbox.children[this.focusedOptionIndex].scrollIntoView({
                    block: "center",
                })
            },

            init: function () {
                this.options = this.data

                if (!(this.value in this.options)) this.value = null

                this.$watch('search', ((value) => {
                    if (!this.open || !value) return this.options = this.data

                    this.options = Object.keys(this.data)
                        .filter((key) => this.data[key].toLowerCase().includes(value.toLowerCase()))
                        .reduce((options, key) => {
                            options[key] = this.data[key]
                            return options
                        }, {})
                }))
            },

            selectOption: function () {
                if (!this.open) return this.toggleListboxVisibility()

                this.value = Object.keys(this.options)[this.focusedOptionIndex]

                this.closeListbox()
            },

            toggleListboxVisibility: function () {
                if (this.open) return this.closeListbox()

                this.focusedOptionIndex = Object.keys(this.options).indexOf(this.value)

                if (this.focusedOptionIndex < 0) this.focusedOptionIndex = 0

                this.open = true

                this.$nextTick(() => {
                    this.$refs.search.focus()

                    this.$refs.listbox.children[this.focusedOptionIndex].scrollIntoView({
                        block: "center"
                    })
                })
            },
        }
    }
</script>
