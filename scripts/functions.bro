module Intel;

function Intel::add_rule(r: Intel::Rule) {
  Intel::indicator_rules[r$rid] = r;
}

function Intel::delete_rule(r: Intel::Rule) {
  delete Intel::indicator_rules[r$rid];
}

# given a connection and a rule, check if the connection matches the rule's indicators and condition
function Intel::check_indicator_logic(r: Intel::Rule, c: connection): bool {
  switch (r$i_condition) {

    case Intel::OR:
    for (each_iid in r$iids) {
      if (each_iid in Intel::indicator_cache[c$uid]) {
        return T;
        break;
      }
    }
    break;

    case Intel::AND:
    for (each_iid in r$iids) {
      if (each_iid !in Intel::indicator_cache[c$uid]) {
        return F;
      }
    }
    return T;
    break;

    case Intel::NONE:
    local none_iid_match: bool = T;
    for (each_iid in r$iids) {
      if (each_iid in Intel::indicator_cache[c$uid]) {
        none_iid_match = F;
        break;
      }
    }
    if (none_iid_match) {
      return T;
    }
    break;

    case Intel::XOR:
    local one_iid_match: bool = F;
    for (each_iid in r$iids) {
      if (each_iid in Intel::indicator_cache[c$uid]) {
        if (one_iid_match) {
          one_iid_match = F;
          break;
        }
        one_iid_match = T;
      }
    }
    if (one_iid_match) {
      return T;
    }
    break;

  }

  return F;
}

# given a connection and a nested rule, check if the connection matches the rule's rules and condition
function Intel::check_rule_logic(r: Intel::Rule, c: connection): bool {
  switch (r$r_condition) {

    case Intel::OR:
    for (each_rid in r$rids) {
      if ( Intel::check_indicator_logic(Intel::indicator_rules[each_rid], c) ) {
        return T;
        break;
      }
    }
    break;

    case Intel::AND:
    for (each_rid in r$rids) {
      if (! Intel::check_indicator_logic(Intel::indicator_rules[each_rid], c) ) {
        return F;
        break;
      }
    }
    return T;
    break;

    case Intel::NONE:
    local none_rid_match: bool = T;
    for (each_rid in r$rids) {
      if ( Intel::check_indicator_logic(Intel::indicator_rules[each_rid], c) ) {
        none_rid_match = F;
        break;
      }
    }
    if (none_rid_match) {
      return T;
    }
    break;

    case Intel::XOR:
    local one_rid_match: bool = F;
    for (each_rid in r$rids) {
      if ( Intel::check_indicator_logic(Intel::indicator_rules[each_rid], c) ) {
        if (one_rid_match) {
          one_rid_match = F;
          break;
        }
        one_rid_match = T;
      }
    }
    if (one_rid_match) {
      return T;
    }
    break;

  }
  return F;
}
