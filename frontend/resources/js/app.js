require('./bootstrap');

import Alpine from 'alpinejs';
import Swal from 'sweetalert2';
import confetti from 'canvas-confetti';

window.Alpine = Alpine;
window.Swal = Swal;


Livewire.on('confetti', () => {
    confetti({
        particleCount: 80,
        spread: 200,
        origin: {y: 0.6}
    });
})

Alpine.start();
