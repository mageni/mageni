###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_45210.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# AWStats Unspecified 'LoadPlugin' Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:awstats:awstats";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103041");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-25 13:20:03 +0100 (Tue, 25 Jan 2011)");
  script_bugtraq_id(45210);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2010-4369");

  script_name("AWStats Unspecified 'LoadPlugin' Directory Traversal Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("awstats_detect.nasl");
  script_mandatory_keys("awstats/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"AWStats is prone to an unspecified directory-traversal vulnerability because
it fails to sufficiently sanitize user-supplied input data.

Versions prior to AWStats 7.0 are vulnerable.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45210");
  script_xref(name:"URL", value:"http://awstats.sourceforge.net/docs/awstats_changelog.txt");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/?func=detail&aid=2537928&group_id=13764&atid=113764");
  script_xref(name:"URL", value:"http://awstats.sourceforge.net/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "7.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "7.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
