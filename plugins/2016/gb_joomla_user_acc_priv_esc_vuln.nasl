###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_user_acc_priv_esc_vuln.nasl 11323 2018-09-11 10:20:18Z ckuersteiner $
#
# Joomla Core Privilege Escalation Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809765");
  script_version("$Revision: 11323 $");
  script_cve_id("CVE-2016-9838");
  script_bugtraq_id(94893);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 12:20:18 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-16 12:43:30 +0530 (Fri, 16 Dec 2016)");

  script_name("Joomla Core Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to incorrect use of
  unfiltered data stored to the session on a form validation.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to gain elevated privileges and modify account information
  for existing user accounts.");

  script_tag(name:"affected", value:"Joomla core versions 1.6.0 through 3.6.4");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.6.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/664-20161201-core-elevated-privileges.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE))
  exit(0);

if(!jVer = get_app_version(cpe:CPE, port:jPort))
  exit(0);

if(version_in_range(version:jVer, test_version:"1.6.0", test_version2:"3.6.4"))
{
  report = report_fixed_ver( installed_version:jVer, fixed_version:"3.6.5");
  security_message( data:report, port:jPort);
  exit(0);
}

exit(0);
