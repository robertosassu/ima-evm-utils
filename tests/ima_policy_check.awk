#! /usr/bin/awk -f 
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2023 Roberto Sassu <roberto.sassu@huawei.com>
#
# Check possible interference of a new rule with the existing IMA policy.

# Documentation/ABI/testing/ima_policy (Linux kernel)
# base:	[[func=] [mask=] [fsmagic=] [fsuuid=] [fsname=]
#	[uid=] [euid=] [gid=] [egid=]
#	[fowner=] [fgroup=]]
# lsm:	[[subj_user=] [subj_role=] [subj_type=]
#	[obj_user=] [obj_role=] [obj_type=]]
# option:	[digest_type=] [template=] [permit_directio]
#		[appraise_type=] [appraise_flag=]
#		[appraise_algos=] [keyrings=]
#
# Non interference if:
# - non-overlapping rules (different values for policy keywords)
# - overlapping rules with same action and same policy options
#
# Rules overlap if they have different policy keywords or same policy keywords
# and same values.
#
# The same policy options and value requirement is needed as otherwise tests
# might match an overlapping rule with undesired/missing policy options.
#
# Rules with MMAP_CHECK and MMAP_CHECK_REQPROT are considered as an exception.
# They overlap, despite they have a different name. In addition, combinations of
# them are reported as interference, since they are matched depending on
# external factors, not inferrable from the policy (a MMAP_CHECK rule might
# cause a measurement, while a MMAP_CHECK_REQPROT one might not).
#
# More/less specific rules are considered as overlapping.
#
# Overlapping rules must have the same policy options, or tests might match
# policy rules set by other tests with undesired policy options.

BEGIN {
	keywords_str="func mask fsmagic fsuuid fsname uid euid gid egid fowner fgroup subj_user subj_role subj_type obj_user obj_role obj_type";
	split(keywords_str, keywords_array, " ");
	options_str="digest_type template permit_directio appraise_type appraise_flag appraise_algos keyrings";
	split(options_str, options_array, " ");
	key_type_unknown=0;
	key_type_keyword=1;
	key_type_option=2;
	for (keyword in keywords_array)
		key_types[keywords_array[keyword]]=key_type_keyword;
	for (option in options_array)
		key_types[options_array[option]]=key_type_option;
	new_rule=1;
	mmap_check_interference=0;
}
{
	if (new_rule) {
		new_rule_action=$1;
		# Strip dont_ from the action of the new rule.
		new_rule_action_sub=new_rule_action;
		gsub(/dont_/, "", new_rule_action_sub);
	} else {
		current_action=$1;
		# Strip dont_ from the action of the current rule.
		current_action_sub=current_action;
		gsub(/dont_/, "", current_action_sub);
		# Unrelated action, ignore.
		if (new_rule_action_sub != current_action_sub) {
			next;
		}
		# Store policy options of the new rule into an array, to compare with the options of the current rule.
		delete new_rule_extra_options;
		for (key in new_rule_array) {
			if (key_types[key] == key_type_option) {
				new_rule_extra_options[key]=new_rule_array[key];
			}
		}
		current_rule_extra_options=0;
	}
	for (i=2; i<=NF; i++) {
		# Parse key/value pair.
		split($i, key_value_array, "=");
		key=key_value_array[1];
		value=key_value_array[2];
		if (key == "func") {
			# Normalize values of IMA hooks.
			if (value == "FILE_MMAP") {
				value="MMAP_CHECK";
			} else if (value == "PATH_CHECK") {
				value="FILE_CHECK";
			}
		}
		# Store key/value pair from the new rule into an array.
		if (new_rule) {
			# Check if the key is valid.
			if (key_types[key] == key_type_unknown) {
				exit 1;
			}
			new_rule_array[key]=value;
		} else {
			if (key_types[key] == key_type_keyword) {
				# No overlap and no operators, no interference.
				if (key in new_rule_array && new_rule_array[key] != value && value !~ /^[<,>,^]/) {
					# Exception: MMAP_CHECK and MMAP_CHECK_REQPROT overlap and have different behavior, interference if overlap (cannot be determined yet).
					if (key == "func" && new_rule_array[key] ~ /MMAP_CHECK/ && value ~ /MMAP_CHECK/) {
						mmap_check_interference=1;
						continue;
					}
					next;
				}
			} else if (key_types[key] == key_type_option) {
				# Possible overlap and different policy options, interference if overlap (cannot be determined yet).
				if (!(key in new_rule_extra_options)) {
					current_rule_extra_options=1;
				# Possible overlap and same policy option, current option can be deleted from the new_rule_extra_options array.
				} else if (new_rule_extra_options[key] == value) {
					delete new_rule_extra_options[key];
				}
				# Possible overlap and same policy options but with different value, interference if overlap (cannot be determined yet).
			}
		}
	}
	# Always ok to parse a new rule.
	if (new_rule) {
		new_rule=0;
		next;
	}
	# Overlap and different related action, interference.
	if (current_action != new_rule_action) {
		exit 1;
	}
	# Overlap and different policy options or different option value, interference.
	for (key in new_rule_extra_options) {
		exit 1;
	}
	if (current_rule_extra_options) {
		exit 1;
	}
	# Overlap and MMAP_CHECK/MMAP_CHECK_REQPROT, interference.
	if (mmap_check_interference) {
		exit 1;
	}
	# Overlap with same related action and same policy options, ok.
}
