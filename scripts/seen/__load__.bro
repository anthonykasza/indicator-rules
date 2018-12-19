@load ./http-url-path
@load ./http-status


# To extend connection record fields:
#  1. create a new script which hooks an event and calls an Intel::Seen
#  2. Add that script to this file to ensure it gets loaded
#  3. Expand the enums in where-locations to include the fields and values passed to Intel:Seen in step 1
