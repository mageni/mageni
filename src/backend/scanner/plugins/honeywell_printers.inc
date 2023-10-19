# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array containing the URL for a Honeywell printer detection
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
function get_honeywell_detect_urls() {

  local_var honeywell_detect_urls;

  honeywell_detect_urls = make_array();

  # nb: As the GUI hasn't any clear "product type" anchor to be used, might allow to change the
  # title HTML tag and has multiple "home_concent_title" HTML tags for various info we're specifying
  # a more strict model pattern here based on the model overview at:
  # https://sps.honeywell.com/us/en/products/productivity/printers
  # Examples:
  # PC45D
  # <div class="home_concent_title">PC42tp</div>
  # <div class="home_concent_title">PM43</div>
  # PX940
  # PD45
  #
  # nb:
  # - The model regex below should be checked from time to time to include possible additional
  #   models
  # - While both URLs contains the same info we're still checking both just to be sure
  honeywell_detect_urls["/index.lua"] =                 'honeywell_logo\\.png.+>Printer Information<.+("home_concent_title">(P[CMXD][^<]+)<)';
  honeywell_detect_urls["/main/home.lua?pageid=Home"] = 'honeywell_logo\\.png.+>Printer Information<.+("home_concent_title">(P[CMXD][^<]+)<)';

  return honeywell_detect_urls;
}
