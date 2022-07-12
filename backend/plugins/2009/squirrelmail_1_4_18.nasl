###############################################################################
# OpenVAS Vulnerability Test
# $Id: squirrelmail_1_4_18.nasl 14033 2019-03-07 11:09:35Z cfischer $
#
# SquirrelMail Prior to 1.4.18 Multiple Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = 'cpe:/a:squirrelmail:squirrelmail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100203");
  script_version("$Revision: 14033 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 12:09:35 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-14 20:19:12 +0200 (Thu, 14 May 2009)");
  script_bugtraq_id(34916);
  script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("SquirrelMail Prior to 1.4.18 Multiple Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("squirrelmail_detect.nasl");
  script_mandatory_keys("squirrelmail/installed");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"SquirrelMail is prone to multiple vulnerabilities, including
  multiple session-fixation issues, a code-injection issue, and multiple cross-site scripting issues.");

  script_tag(name:"impact", value:"Attackers may exploit these issues to execute arbitrary script code
  in the browser of an unsuspecting user, to hijack the session of a valid user, or to inject and execute
  arbitrary PHP code in the context of the webserver process. This may facilitate a compromise of the
  application and the computer. Other attacks are also possible.");

  script_tag(name:"affected", value:"Versions prior to SquirrelMail 1.4.18 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34916");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 1.4.18 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.4.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.18");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);