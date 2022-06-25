###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_merak_mail_server_mult_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# IceWarp Merak Mail Server Multiple Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:icewarp:mail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800388");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2009-1467", "CVE-2009-1468", "CVE-2009-1469");
  script_bugtraq_id(34823, 34820, 34827, 34825);

  script_name("IceWarp Merak Mail Server Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1253");
  script_xref(name:"URL", value:"http://www.redteam-pentesting.de/advisories/rt-sa-2009-001");
  script_xref(name:"URL", value:"http://www.redteam-pentesting.de/advisories/rt-sa-2009-002");
  script_xref(name:"URL", value:"http://www.redteam-pentesting.de/advisories/rt-sa-2009-003");
  script_xref(name:"URL", value:"http://www.redteam-pentesting.de/advisories/rt-sa-2009-004");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_web_detect.nasl");
  script_mandatory_keys("icewarp/installed");

  script_tag(name:"impact", value:"Successful attacks will allow attackers to inject arbitrary web script or
  HTML script code via a specially crafted email in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Merak Mail Server prior to 9.4.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Merak Mail Server 9.4.2.");

  script_tag(name:"summary", value:"The host is running Merak Mail Server and is prone to Cross-Site Script
  vulnerabilities.");

  script_tag(name:"insight", value:"- Error in cleanHTML function in server/inc/tools.php is related to the email
  view and incorrect processing of HTML filtering.

  - Error in getHTML function in server/inc/rss/item.php is related to title, link, or description element in an RSS feed.

  - Error exists in search form in server/webmail.php in the Groupware component via 'sql' and 'order_by' elements
  in an XML search query.

  - Error occur in Forgot Password implementation in server/webmail.php via CRLF sequences preceding a Reply-To
  header in the subject element of an XML document.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!merakVer = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_less(version: merakVer, test_version: "9.4.2")) {
  report = report_fixed_ver(installed_version: merakVer, fixed_version: "9.4.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);