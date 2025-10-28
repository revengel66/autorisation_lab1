document.addEventListener('DOMContentLoaded', () => {
    attachZeroFallback();

    const modalEl = document.getElementById('notification');
    if (!modalEl) {
        return;
    }
    const shouldShowModal = modalEl.dataset.show === 'true';
    if (!shouldShowModal) {
        return;
    }

    if (typeof bootstrap === 'undefined' || !bootstrap.Modal) {
        console.warn('Bootstrap modal component is not available.');
        return;
    }

    const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
    modal.show();

    const shouldReload = modalEl.dataset.reload === 'true';
    modalEl.addEventListener('hidden.bs.modal', () => {
        if (shouldReload) {
            window.location.reload();
        }
    });

});

function attachZeroFallback() {
    const fields = ['length', 'month'];
    fields.forEach((fieldId) => {
        const input = document.getElementById(fieldId);
        if (!input) {
            return;
        }
        const ensureZero = () => {
            if (input.value.trim() === '') {
                input.value = '0';
            }
        };
        input.addEventListener('blur', ensureZero);
        input.addEventListener('change', ensureZero);
    });
}
