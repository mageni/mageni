###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_titan_ftp_server_bof_vuln.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# Titan FTP Server DELE Command Remote Buffer Overflow Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:southrivertech:titan_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800073");
  script_version("2019-04-09T13:55:37+0000");
  script_tag(name:"last_modification", value:"2019-04-09 13:55:37 +0000 (Tue, 09 Apr 2019)");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5281", "CVE-2008-0702", "CVE-2008-0725");
  script_bugtraq_id(27611);
  script_name("Titan FTP Server DELE Command Remote Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_titan_ftp_detect.nasl");
  script_mandatory_keys("TitanFTP/detected");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/0802-exploits/titan-heap-py.txt");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28760");

  script_tag(name:"impact", value:"Successful exploitation will cause a denial of service.");

  script_tag(name:"affected", value:"Titan FTP Server version 6.05 build 550 and prior.");

  script_tag(name:"insight", value:"The flaw exists in server due to improper handling of input passed to the
  DELE command.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"summary", value:"This host is running Titan FTP Server and is prone to a remote
  buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "6.05.550")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Unknown");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);