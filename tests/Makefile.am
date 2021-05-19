check_SCRIPTS =
TESTS = $(check_SCRIPTS)

check_SCRIPTS += ima_hash.test sign_verify.test boot_aggregate.test \
		 portable_signatures.test verify_evmsig.test \
		 evm_hmac_non_enabled_xattrs.test

clean-local:
	-rm -f *.txt *.out *.sig *.sig2

distclean: distclean-keys
.PHONY: distclean-keys
distclean-keys:
	./gen-keys.sh clean
