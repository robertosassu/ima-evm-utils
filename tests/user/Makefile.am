check_SCRIPTS =
TESTS = $(check_SCRIPTS)

check_SCRIPTS += ima_hash.test sign_verify.test ima_policy_check.test

.PHONY: check_logs
check_logs:
	@for log in $(TEST_LOGS); do \
	   echo -e "\n***" $$log "***" ; \
	   case $$log in \
	   ima_hash.log | sign_verify.log ) \
	       tail -3 $$log ; \
	       grep "skipped" $$log && grep "skipped" $$log | wc -l ;; \
	   *) \
	       cat $$log ;; \
	   esac ; \
	done

clean-local:
	-rm -f *.txt *.out *.sig *.sig2

distclean: distclean-keys

shellcheck:
	shellcheck $(check_SCRIPTS)

.PHONY: distclean-keys shellcheck
distclean-keys:
	../gen-keys.sh clean
