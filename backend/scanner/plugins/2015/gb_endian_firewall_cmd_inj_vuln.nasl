###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_endian_firewall_cmd_inj_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Endian Firewall OS Command Injection Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:endian_firewall:endian_firewall";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805758");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5082");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-12 17:26:17 +0530 (Mon, 12 Oct 2015)");
  script_name("Endian Firewall OS Command Injection Vulnerability");

  script_tag(name:"summary", value:"This host is running Endian Firewall
  and is prone to command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to 'NEW_PASSWORD_1' or
  'NEW_PASSWORD_2' parameter to  cgi-bin/chpasswd.cgi are not properly filtered.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Endian Firewall before version 3.0.");

  script_tag(name:"solution", value:"Upgrade to Endian Firewall version 3.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/37426");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/37428");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_endian_firewall_version.nasl");
  script_mandatory_keys("endian_firewall/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.endian.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

if(version_is_less(version:appVer, test_version:"3.0.0"))
{
  report = 'Installed version: ' + appVer + '\n' +
           'Fixed version:      3.0.0'   + '\n';
  security_message(data:report, port:appPort);
  exit(0);
}
