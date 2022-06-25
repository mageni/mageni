##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_xss_vuln02.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# DokuWiki Stored XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:dokuwiki:dokuwiki';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112025");
  script_version("$Revision: 12391 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-22 10:27:42 +0200 (Tue, 22 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-12979", "CVE-2017-12980");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DokuWiki Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_mandatory_keys("dokuwiki/installed");

  script_tag(name:"summary", value:"DokuWiki has stored XSS when rendering a malicious RSS or Atom feed or language name in a code element, in /inc/parser/xhtml.php. An attacker can create or edit a wiki with this element to trigger   JavaScript execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"DokuWiki version 2017-02-19c and prior.");

  script_tag(name:"solution", value:"Upgrade to pull request #2083 and/or #2086 respectively to fix the issues.");

  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/2080");
  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/2081");

  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2017-02-19c")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references.");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
