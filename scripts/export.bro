module Intel;

export {
  const read_rules_files: set[string] = {} &redef;
  redef enum Notice::Type += { Intel::Rule_Notice };

  # a condition to apply to multiple indicators or rules
  type Condition: enum {
    # any (not exclusive) 
    OR,
    # all
    AND,
    # none - this may be computationally expensive
    NONE,
    # any but not more than one (exclusive) 
    XOR,
   };

  type Rule: record  {
    # condition to apply to included indicators
    i_condition:	Condition &default=OR;
    # set of indicators to monitor for
    iids:		set[string] &default=set();
    # rule identification string
    rid:		string;
    # set of rules to monitor for
    rids:		set[string] &default=set();
    # condition to apply to included rules
    r_condition:	Condition &default=OR;
    # do you want to get notices about this rule firing?
    do_rules_notice: bool &default=F;
  };

  redef record Intel::MetaData += {
    # indicator identification string
    iid:	string &optional;
  };

  # interface to add rules or remove rules. 
  # to update a rule, simply re-add it
  global add_rule: function(r: Rule);
  global delete_rule: function(r: Rule);

  # Rule indexed by rid, rid=>[Rule]
  global indicator_rules: table[string] of Rule &redef;

  # set of indicators indexed by connection UID, uid=>[iid, iid, iid]
  global indicator_cache: table[string] of set[string] &redef;
}
