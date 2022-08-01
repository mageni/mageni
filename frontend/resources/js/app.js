require('./bootstrap');

import Alpine from 'alpinejs';
import confetti from 'canvas-confetti';

window.Alpine = Alpine;

Livewire.on('confetti', () => {
    confetti({
        particleCount: 80,
        spread: 200,
        origin: {y: 0.6}
    });
})

Alpine.start();
