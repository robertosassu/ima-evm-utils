check_SCRIPTS =
TESTS = $(check_SCRIPTS)

check_SCRIPTS += ima_hash.test sign_verify.test boot_aggregate.test \
		 portable_signatures.test ima_skip_measurement_audit.test \
		 ima_meta_immutable.test evm_hash_algo_hmac.test \
		 ima_policies.test evm_command_line.test

clean-local:
	-rm -f *.txt *.out *.sig *.sig2

distclean: distclean-keys
.PHONY: distclean-keys
distclean-keys:
	./gen-keys.sh clean
