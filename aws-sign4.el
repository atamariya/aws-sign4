;;;;  aws-sign4
;;;;
;;;;  Copyright (C) 2013 Thomas Bakketun <thomas.bakketun@copyleft.no>
;;;;  Elisp version author: Anand Tamariya
;;;;
;;;;  This library is free software: you can redistribute it and/or modify
;;;;  it under the terms of the GNU Lesser General Public License as published
;;;;  by the Free Software Foundation, either version 3 of the License, or
;;;;  (at your option) any later version.
;;;;
;;;;  This library is distributed in the hope that it will be useful,
;;;;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;;  GNU General Public License for more details.
;;;;
;;;;  You should have received a copy of the GNU General Public License
;;;;  along with this library.  If not, see <http://www.gnu.org/licenses/>.

;; Documentation: https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

(require 'hmac)

(defun hash (data)
  (secure-hash 'sha256 data))

(defun create-canonical-path (path)
  (let ((input (split-string path "/"))
        (output nil))
    (loop while input do
          (cond ((or (string= (car input) "")
                     (string= (car input) "."))
                 (unless (cdr input)
                   (push "" output)))
                ((string= (car input) "..")
                 (pop output))
                (t
                 (push (car input) output)))
          (pop input))
    (setq output (reverse output))
    (push "" output)
    (mapconcat (lambda (x)
		 (url-encode-url x))
               output "/")))

(defun create-canonical-query-string (params)
  (mapconcat #'identity
	     (loop for (key . value) in
		   (sort params
			 (lambda (a b)
			   (string< (car a) (car b))))
		   collect (format "%s=%s"
				   (url-encode-url key)
				   (url-hexify-string
				    (format "%s"
					    (if (listp value)
						(car value) value)))))
	      "&"))

(defun trimall (string)
  (string-trim string))

(defun merge-duplicate-headers (headers)
  (loop for header = (pop headers)
        while header
        collect `(,(car header)
                  ,@(cons (cdr header)
                          (loop while (equal (car header) (caar headers))
                                collect (cdr (pop headers)))))))

(defun create-canonical-headers (headers)
  ;; (merge-duplicate-headers
   (sort (loop for (key . value) in headers
               collect (cons (downcase (trimall key)) value))
	 (lambda (a b)
	   (string< (car a) (car b)))
	 ))

(defun create-signed-headers (canonical-headers)
  (mapconcat #'car canonical-headers ";"))

(defun create-canonical-request (method canonical-path canonical-query-string
					canonical-headers signed-headers payload)
  (with-temp-buffer
    ;; HTTPRequestMethod:
    (insert (upcase method))
    (insert "\n")
    ;; CanonicalURI:
    (insert canonical-path)
    (insert "\n")
    ;; CanonicalQueryString:
    (insert canonical-query-string)
    (insert "\n")
    ;; CanonicalHeaders:
    (dolist (header canonical-headers)
      (insert (format "%s:%s\n" (car header) (cdr header))))
    (insert "\n")
    ;; SignedHeaders
    (insert signed-headers)
    (insert "\n")
    ;; Payload
    (insert (hash (or payload "")))
    (buffer-string)))

(defun string-to-sign (request-date credential-scope canonical-request)
  (with-temp-buffer
    (insert "AWS4-HMAC-SHA256")
    (insert "\n")
    (insert request-date)
    (insert "\n")
    (insert credential-scope)
    (insert "\n")
    (insert (hash canonical-request))
    (buffer-string)))

(defun hmac1 (key data &optional binary)
  (hmac 'sha256 key data binary))

(defun calculate-signature (k-secret string-to-sign date region service)
  (with-coding-priority '(iso-8859-1)
    (let* ((k-date (hmac1 (concat "AWS4" k-secret) date t))
           (k-region (hmac1 k-date region t))
           (k-service (hmac1 k-region service t))
           (k-signing (hmac1 k-service "aws4_request" t)))
      (hmac1 k-signing string-to-sign))))

(defvar *aws-credentials* nil)

(defun get-credentials ()
  (unless (functionp *aws-credentials*)
    (error "Please bind *AWS-CREDENTIALS* to a function."))
  (funcall *aws-credentials*))

(defun aws-sign4 (&rest request)
  (let* ((region (plist-get request :region))
         (service (plist-get request :service))
         (host (plist-get request :host))
         (path (or (plist-get request :path) "/"))
         (params (plist-get request :params))
         (headers (plist-get request :headers))
         (payload (plist-get request :payload))
         (method (or (plist-get request :method)
		     (if payload "POST" "GET")))
         (request-date (plist-get request :request-date))
         (expires (plist-get request :expires))
         (scheme (or (plist-get request :scheme) "https"))
	 (access-key (nth 0 (get-credentials)))
	 (private-key (nth 1 (get-credentials)))
	 )
    (check-type service (and (not null) (or symbol string))
		"an AWS service designator")
    (check-type path string)
    (let* ((x-amz-date (or request-date
			   (format-time-string "%Y%m%dT%H%M%SZ" nil "UTC0")))
           (scope-date (substring x-amz-date 0 8))
           (region (downcase region))
           (service (etypecase service
                      (symbol (downcase service))
                      (string service)))
           (credential-scope (format "%s/%s/%s/aws4_request"
				     scope-date region service)))
      (unless host
        (error "Error in arguments to aws-sign4. Missing host."))
      (push (cons "Host" host) headers)
      (unless expires
        (pushnew (cons "x-amz-date" x-amz-date) headers
		 :key #'car :test #'string-equal))
      (let* ((canonical-headers (create-canonical-headers headers))
	     (signed-headers (create-signed-headers canonical-headers)))
        (when expires
          (push (cons "X-Amz-Algorithm" "AWS4-HMAC-SHA256") params)
          (push (cons "X-Amz-Credential" (format "%s/%s"
                                                 access-key
                                                 credential-scope))
                params)
          (push (cons "X-Amz-Date" x-amz-date) params)
          (push (cons "X-Amz-Expires" (number-to-string expires)) params)
          (push (cons "X-Amz-SignedHeaders" signed-headers) params))
        (let* ((canonical-path (create-canonical-path path))
               (canonical-query-string (create-canonical-query-string params))
               (creq (create-canonical-request
		      method canonical-path canonical-query-string
		      canonical-headers signed-headers payload))
               (sts (string-to-sign x-amz-date
				    credential-scope
				    creq))
               (signature (calculate-signature private-key
                                               sts
                                               scope-date
                                               region
                                               service)))
          (list
           (if expires
               (format "%s://%s%s?%s&X-Amz-Signature=%s"
                       (downcase scheme)
                       host
                       canonical-path
                       canonical-query-string
                       signature)
             (format "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
                     access-key
                     credential-scope
                     signed-headers
                     signature))
           x-amz-date
           creq
           sts
           credential-scope
           signed-headers
           signature))))
    ))

(defun aws-url-retrieve (url &optional auth-header region payload headers
			     service method)
  (let* ((url-obj (url-generic-parse-url url))
	 (service (or service
		      (and (string-match "\\." (url-host url-obj))
			   (substring (url-host url-obj) 0 (match-beginning 0)))))
	 (fullpath (url-path-and-query url-obj))
	 (path (car fullpath))
	 (query (if (cdr fullpath)
		    (reverse (url-parse-query-string (cdr fullpath)))))
	 (url-request-method (or method (if payload "POST" "GET")))

	 (auth (aws-sign4 :region (or region "us-east-1")
			  :service service
			  :host (url-host url-obj)
			  :path path
			  :params query
			  :payload payload
			  :headers headers
			  :method method
			  ;; :request-date "20221021T070304Z"
			  :expires (unless auth-header 300)
			  )))
    ;; (message "%s" auth)

    (with-current-buffer
	(if (or auth-header payload)
	    (let* ((url-request-extra-headers
		    (append headers
			    `(("Authorization" . ,(car auth))
			      ("x-amz-date" . ,(nth 1 auth))
			      )))
		   (url-request-data payload))
	      (url-retrieve-synchronously url))
	  (url-retrieve-synchronously (car auth)))
      (buffer-string))
    ))

(provide 'aws-sign4)
