/* main.js – Encrypted Traffic Threat Detector dashboard */

(function () {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Sidebar toggle                                                       */
  /* ------------------------------------------------------------------ */
  var toggleBtn = document.getElementById('sidebarToggle');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', function () {
      if (window.innerWidth <= 768) {
        document.body.classList.toggle('sidebar-open');
      } else {
        document.body.classList.toggle('sidebar-collapsed');
      }
    });

    // Close sidebar when clicking the overlay (mobile)
    document.addEventListener('click', function (e) {
      if (
        window.innerWidth <= 768 &&
        document.body.classList.contains('sidebar-open') &&
        !e.target.closest('#sidebar') &&
        !e.target.closest('#sidebarToggle')
      ) {
        document.body.classList.remove('sidebar-open');
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /* Dropzone drag-and-drop highlighting                                  */
  /* ------------------------------------------------------------------ */
  var dropzone = document.getElementById('dropzone');
  if (dropzone) {
    ['dragenter', 'dragover'].forEach(function (evt) {
      dropzone.addEventListener(evt, function (e) {
        e.preventDefault();
        dropzone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(function (evt) {
      dropzone.addEventListener(evt, function (e) {
        e.preventDefault();
        dropzone.classList.remove('dragover');
      });
    });

    dropzone.addEventListener('drop', function (e) {
      var fileInput = document.getElementById('fileInput');
      if (fileInput && e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        fileInput.dispatchEvent(new Event('change'));
      }
    });

    dropzone.addEventListener('click', function (e) {
      if (e.target.tagName !== 'INPUT') {
        var fileInput = document.getElementById('fileInput');
        if (fileInput) fileInput.click();
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /* Auto-dismiss flash messages after 6 seconds                         */
  /* ------------------------------------------------------------------ */
  setTimeout(function () {
    document.querySelectorAll('.alert.alert-dismissible').forEach(function (el) {
      var bsAlert = bootstrap.Alert.getOrCreateInstance(el);
      if (bsAlert) bsAlert.close();
    });
  }, 6000);

  /* ------------------------------------------------------------------ */
  /* Confirm dialogs for destructive actions                             */
  /* ------------------------------------------------------------------ */
  document.querySelectorAll('[data-confirm]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      if (!window.confirm(el.dataset.confirm)) {
        e.preventDefault();
      }
    });
  });

})();
