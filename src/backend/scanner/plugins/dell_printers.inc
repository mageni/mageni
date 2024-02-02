# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array containing the URL for a Dell printer detection
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
function get_dell_detect_urls() {
  local_var dell_detect_urls;

  dell_detect_urls = make_array();

  dell_detect_urls["/"]                         = "<TITLE>Dell ([^ ]+) Laser Printer</TITLE>";   # Dell B2360dn Laser Printer
  dell_detect_urls["/frametop.htm"]             = "<title>Dell (Color [^<]+)</title>";           # Dell Color MFP H625cdw
  dell_detect_urls["/Information/general.htm"]  = "Model Name&nbsp;:[^>]+>[^>]+>(.* Laser MFP)"; # 1135n Laser MFP
  dell_detect_urls["/port_255/topbar"]          = "<h5>Dell Laser Printer ([^<]+)</h5>";         # Dell Laser Printer 1710n
  dell_detect_urls["/ews/frametop.htm"]         = "<title>Dell (MFP [^<]+)</title>";             # Dell MFP Laser 3115cn
  dell_detect_urls["/general/information.html"] = "<title>Dell (MFP [^<]+)</title>";             # Dell MFP E515dw
  dell_detect_urls["/default.html"]             = "<TITLE>Dell (Laser MFP.*)</TITLE>";

  return dell_detect_urls;
}
