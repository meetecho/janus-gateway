;; Include this in your ~/.emacs file for editing Janus code in Emacs.

;; Run "M-x janus-mode" to set the coding style for Janus.
(defun janus-mode ()
  "Sets the Janus coding style in c-mode."
  (interactive)
  ;; c-basic-offset and tab-width can be set to personal preference as long as
  ;; they are the same. They will expand to the single tab required by the Janus
  ;; coding style.
  (setq c-basic-offset 2
        tab-width 2
        indent-tabs-mode t)
  (c-set-offset 'arglist-intro '+)
  (c-set-offset 'arglist-cont-nonempty '+)
  (c-set-offset 'case-label '+))
