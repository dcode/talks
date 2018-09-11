@load base/frameworks/intel
@load frameworks/intel/seen
@load frameworks/intel/do_notice

redef Intel::read_files += {
    @DIR + "/bad-symantec-certs.dat"
};
