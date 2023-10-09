# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var prestashop_modules_info;

# nb:
# - The format is: "[MODULE_SLAG]", "[NAME]#---#[DETECTION PATTERN]#---#[VERSION REGEX]#---#[CPE]#---#[MODULE-PAGE PATH]"
# - To make sure that we're not using two or more entries for the same file in this array (When e.g.
#   having two entries the foreach(keys()) loop in the detection VT would iterate over both items
#   but the infos variable in both iterations would only include the info from one of both entries
#   two times) we can use something like e.g. the following:
#   egrep -o '^  "[^"]+",' prestashop_modules.inc | sort | uniq -d
#
prestashop_modules_info = make_array(
  "dashproducts", "Dashboard Products#---#<displayName><!\[CDATA\[Dashboard Products#---#<version><!\[CDATA\[([0-9.]+)\]\]><\/version>#---#cpe:/a:prestashop:dashboard_products#---#15252-dashboard-products"
);
