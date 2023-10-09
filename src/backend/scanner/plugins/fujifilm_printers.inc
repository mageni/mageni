# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array containing the URL for a Fuji Xerox / Fujifilm printer detection
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
function get_fujifilm_detect_urls() {

  local_var fujifilm_detect_urls;

  fujifilm_detect_urls = make_array();

  fujifilm_detect_urls["/globalnav/msg/message_en-US.json"]                      = "(FUJIFILM Business Innovation Corp)";                                     # ApeosPrint eg. ApeosPrint C325/328
  fujifilm_detect_urls["/home/api/about"]                                        = '"DevFrndlName"\\s*:\\s*"([^"]+)"';                                        # Apeos eg. Apeos C5570
  # nb: Some uses "<div", some "<tb" for the 'id ="' part below
  fujifilm_detect_urls["/ews/setting/prtinfo.htm"]                               = "Product Name</font></b></td><td [^>]+><font [^>]+>(DocuPrint [^<]+)";     # DocuPrint e.g. DocuPrint C1110
  fujifilm_detect_urls["/setting/prtinfo.htm"]                                   = "Product Name</td><td class=std_2>((DocuPrint|DocuCentre) [^<]+)";         # DocuPrint or DocuCentre e.g. DocuPrint M355 df, DocuCentre SC2020
  fujifilm_detect_urls["/setting/prtinfo.htm#--avoid-dup2--#"]                   = "Printer Model:</td><td [^>]+>(DocuPrint [^<]+)";                          # DocuPrint e.g. DocuPrint C3290 FS
  fujifilm_detect_urls["/home/msg/message_en-US.json"]                           = '("Fuji Xerox Asset Tag")';                                                # ApeosPort e.g. ApeosPort C3070
  fujifilm_detect_urls["/wt2parser.cgi?home_en"]                                 = '<td align="left" valign="middle" class="name">DC-([0-9]+)[^<]*</td>';     # DocuColor, e.g. DC-260-D44DB8
  fujifilm_detect_urls["/sprt.htm"]                                              = "var prd='((DocuColor|DocuCentre) ?[^']+)'";                               # DocuColor and DocuCentre, e.g. DocuColor 1450 GA, DocuCentre-V C2265

  return fujifilm_detect_urls;
}