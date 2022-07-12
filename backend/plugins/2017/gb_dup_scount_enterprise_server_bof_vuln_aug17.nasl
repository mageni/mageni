##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dup_scount_enterprise_server_bof_vuln_aug17.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Dup Scout Enterprise Server Buffer Overflow Vulnerability - Aug17
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dup:dup_scout_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811718");
  script_version("$Revision: 11863 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-30 18:35:36 +0530 (Wed, 30 Aug 2017)");
  script_name("Dup Scout Enterprise Server Buffer Overflow Vulnerability - Aug17");

  script_tag(name:"summary", value:"The host is running Dup Scout Enterprise
  Server and is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to server.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Dup Scout Enterprise version 10.0.18 and prior.");

  script_tag(name:"solution", value:"Update Dup Scout Enterprise to version 10.2 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42557");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/144995/Dup-Scout-Enterprise-10.0.18-Buffer-Overflow.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_dup_scount_enterprise_detect.nasl");
  script_mandatory_keys("Dup/Scout/Enterprise/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! dupPort = get_app_port(cpe:CPE)) exit(0);
if( ! dupVer = get_app_version(cpe:CPE, port:dupPort)) exit(0);

## Installed 9.0.28, 9.9.14, 10.0.18 ; all are vulnerable
if(version_is_less_equal(version:dupVer, test_version:"10.0.18"))
{
  report = report_fixed_ver( installed_version:dupVer, fixed_version:"10.2");
  security_message(port:dupPort, data:report);
  exit(0);
}
exit(0);
