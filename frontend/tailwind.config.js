const defaultTheme = require('tailwindcss/defaultTheme');

module.exports = {
    purge: [],

    theme: {
        extend: {
            fontFamily: {
                sans: ['Inter', ...defaultTheme.fontFamily.sans],
            },
            extend: {
                opacity: ['disabled'],
            },
        },
    },

    plugins: [require('@tailwindcss/forms'), require('@tailwindcss/typography')],
};

