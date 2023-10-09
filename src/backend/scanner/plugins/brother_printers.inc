# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array containing the URL for a Brother printer detection
#        as the array key and the regex to extract the type/model as the value.
#
# @note The array key might contain a pattern like e.g. (numbers incrementing
#       for multiple same URLs):
#
#       #--avoid-dup1--#
#
#       to be able to have different array keys for the same URL.
#       Make sure to strip such patterns away with ereg_replace
#       in the VT calling this function.
#
# @return An array as described in the function description.
#
function get_brother_detect_urls() {

  local_var brother_detect_urls;

  brother_detect_urls = make_array();

  brother_detect_urls["/admin/firmwareupdate.html?pageid=1100"]  = "<title>Brother ([A-Z0-9-]+)</title>"; # <title>Brother MFC-J475DW</title>
  brother_detect_urls["/general/information.html?kind=item"]  = "<title>Brother ([A-Z0-9-]+) series</title>"; # <title>Brother HL-L2395DW series</title>
  brother_detect_urls["/general/status.html"]  = "<title>Brother ([A-Z0-9-]+)( [sS]eries)?</title>"; # <title>Brother MFC-J1300DW</title>

  return brother_detect_urls;
}