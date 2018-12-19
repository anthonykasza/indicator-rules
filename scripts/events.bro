
module Intel;

event Intel::match(s: Seen, items: set[Item]) &priority=-2 {
  for (each_item in items) {
    if (! each_item$meta?$if_in || s$where == each_item$meta$if_in) {
      if (s$conn$uid in Intel::indicator_cache) {
        add Intel::indicator_cache[s$conn$uid][each_item$meta$iid];
      } else {
        Intel::indicator_cache[s$conn$uid] = set(each_item$meta$iid);
      }
    }
  }
}

event connection_state_remove(c: connection) {
  if (c$uid !in Intel::indicator_cache) return;
  for (r in Intel::indicator_rules) {
    # If the rule consists of a set of indicators and no nested rules
    if ( (|Intel::indicator_rules[r]$rids| == 0) && (|Intel::indicator_rules[r]$iids| > 0) ) {
      # check its indicator logic and notice
      if ( check_indicator_logic(Intel::indicator_rules[r], c) ) {
        if (Intel::indicator_rules[r]$do_rules_notice) { 
          NOTICE( [$note=Intel::Rule_Notice, $conn=c, $msg=fmt("matched on rule: %s", Intel::indicator_rules[r]$rid)] );
        }
      }
    }

    # If the rule consists of nested rules and no indicators
    else if ( (|Intel::indicator_rules[r]$rids| > 0) && (|Intel::indicator_rules[r]$iids| == 0) ) {
      # check its rule logic and notice
      if ( check_rule_logic(Intel::indicator_rules[r], c) ) {
        if (Intel::indicator_rules[r]$do_rules_notice) {
          NOTICE( [$note=Intel::Rule_Notice, $conn=c, $msg=fmt("matched on rule: %s", Intel::indicator_rules[r]$rid)] );
        }
      }
    }

    # If the rule consists of nested rules and indicators
    else if ( (|Intel::indicator_rules[r]$rids| > 0) && (|Intel::indicator_rules[r]$iids| > 0) ) {
      # check its indicator logic and its rule logic, then notice
      if ( (check_indicator_logic(Intel::indicator_rules[r], c)) && (check_rule_logic(Intel::indicator_rules[r], c)) ) {
        if (Intel::indicator_rules[r]$do_rules_notice) {
          NOTICE( [$note=Intel::Rule_Notice, $conn=c, $msg=fmt("matched on rule: %s", Intel::indicator_rules[r]$rid)] );
        }
      }
    }

    # If the rule consists of no nested rules and no indicators
    else {
      Intel::delete_rule(Intel::indicator_rules[r]);
    }
  }

  # when a connection expires, so do all the Intel::match hits that were assocaited with it
  delete Intel::indicator_cache[c$uid];
}

event Intel::read_rule_entry(desc: Input::EventDescription, tpe: Input::Event, r: Intel::Rule) {
  Intel::add_rule(r);
}

event bro_init() &priority=5 {
  if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER ) {
    for ( a_file in read_rules_files ) {
      Input::add_event([$source=a_file,
                        $reader=Input::READER_ASCII,
                        $mode=Input::REREAD,
                        $name=cat("intel_rules-", a_file),
                        $fields=Intel::Rule,
                        $ev=Intel::read_rule_entry]);
    }
  }
}
