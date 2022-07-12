###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_disk_savvy_login_buffer_overflow_vuln_oct.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Disk Savvy Enterprise 9.0.32 - Login Buffer Overflow (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:disksavvy:disksavvy_enterprise_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107101");
  script_version("$Revision: 12149 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-05 11:19:11 +0530 (Mon, 05 Dec 2016)");
  script_name("Disk Savvy Enterprise 9.0.32 - Login Buffer Overflow (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_disk_savvy_enterprise_server_detect.nasl");
  script_mandatory_keys("DiskSavvy/Enterprise/Server/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.disksorter.com");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40854/");

  script_tag(name:"summary", value:"This host is installed with Disk Savvy Enterprise and is prone to multiple vulnerabilities.

  This NVT has been replaced by NVT 'Disk Savvy Enterprise Server Buffer Overflow Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.809486).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to elevate privileges from any account type and execute code.");

  script_tag(name:"affected", value:"Disk Savvy Enterprise 9.0.32");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"9.0.32" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None Available");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );