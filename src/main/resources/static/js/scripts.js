document.addEventListener('DOMContentLoaded', () => {
    const modalEl = document.getElementById('error');
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
