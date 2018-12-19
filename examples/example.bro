@load indicator-rules

# read in an intel file for indicators
redef Intel::read_files += {
  fmt ("%s/data/indicators.dat", @DIR)
};

# rules can also be created in scriptland by calling the Intel::add_rule function
#  Intel::add_rule( [$rid="RID_1", $i_condition=Intel::AND, $iids=set("IID_1", "IID_5")] );
#
# or they can be read in from files through the input framework
redef Intel::read_rules_files += {
  fmt ("%s/data/rules.dat", @DIR)
};

event bro_init() {
  # we suspend processing for a bit so Zeek can ingest indicators and rules before it completes processing our pcap
  suspend_processing();
  # this number is hard coded to the number of rules in data/rules.dat
  # it ensures Bro doesn't begin processing packets before ingesting our rules
  # if you add more rules to the data/rules.dat file you need to adjust this hardcoded value to match
  when (|Intel::indicator_rules| >= 14) {
    continue_processing();
  }
}
