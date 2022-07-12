###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_database_listener_sec_bypass_vuln.nasl 12634 2018-12-04 07:26:26Z cfischer $
#
# Oracle Database Server listener Security Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:oracle:database_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803960");
  script_version("$Revision: 12634 $");
  script_cve_id("CVE-2000-0818");
  script_bugtraq_id(1853);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 08:26:26 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2013-11-06 19:08:11 +0530 (Wed, 06 Nov 2013)");
  script_name("Oracle Database Server listener Security Bypass Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access to an operating
  system account and execute commands.");

  script_tag(name:"affected", value:"Oracle Database Server versions 7.3.4, 8.0.6, and 8.1.6 are affected.");

  script_tag(name:"insight", value:"A flaw exist in Oracle listener program, which allows attacker to cause
  logging information to be appended to arbitrary files and execute commands via the SET TRC_FILE or SET LOG_FILE commands");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisories.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"This host is installed with Oracle Database Server and is prone to security
  bypass vulnerability.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1853");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/5380");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_mandatory_keys("OracleDatabaseServer/installed");
  script_xref(name:"URL", value:"http://metalink.oracle.com");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!ver = get_app_version(cpe:CPE, port:port))exit(0);

if(ver =~ "^(8\.[0|1]\.|7\.3\.)")
{
  if(version_is_equal(version:ver, test_version:"7.3.4") ||
     version_is_equal(version:ver, test_version:"8.0.6") ||
     version_is_equal(version:ver, test_version:"8.1.6"))
  {
    security_message(port);
  }
}
