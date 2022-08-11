###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dm_filemanager_sec_bypass_vuln.nasl 13448 2019-02-04 18:28:31Z cfischer $
#
# DM FileManager 'login.php' Security Bypass Vulnerability
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

CPE = "cpe:/a:dutchmonkey:dm_album";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800819");
  script_version("$Revision: 13448 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-04 19:28:31 +0100 (Mon, 04 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2025", "CVE-2009-1741");
  script_bugtraq_id(35035);
  script_name("DM FileManager 'login.php' Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dm_filemanager_detect.nasl");
  script_mandatory_keys("dm-filemanager/detected");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8903");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8741");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35167");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1532");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker execute arbitrary
  SQL commands when magic_quotes_gpc is disabled and bypass authentication
  and gain administrative access.");

  script_tag(name:"affected", value:"DutchMonkey, DM FileManager version 3.9.2 and prior");

  script_tag(name:"insight", value:"- Error exists when application fails to set the 'USER', 'GROUPID',
  'GROUP', and 'USERID' cookies to certain values in admin/login.php.

  - Error in 'login.php' which fails to sanitise user supplied input via
  the 'Username' and 'Password' fields.");

  script_tag(name:"solution", value:"Upgrade to DM FileManager version 3.9.10 or later.");

  script_tag(name:"summary", value:"The host is running DM FileManager and is prone to a security bypass
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
if(version_is_less_equal(version:vers, test_version:"3.9.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"3.9.10", install_url:infos["location"]);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);