###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powerdns_auth_server_label_decompression_dos_vuln_win.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# PowerDNS Authoritative (Auth) Server Denial of Service Vulnerability (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:powerdns:authoritative_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809857");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2015-1868", "CVE-2015-5470");
  script_bugtraq_id(74306);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-04 15:18:12 +0530 (Wed, 04 Jan 2017)");
  script_name("PowerDNS Authoritative (Auth) Server Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running PowerDNS Authoritative (Auth)
  Server and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  handling of DNS packets by label decompression functionality.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the target service to crash or consume excessive CPU resource.");

  script_tag(name:"affected", value:"PowerDNS Authoritative (Auth) Server 3.2.x,
  3.3.x before 3.3.3, and 3.4.x before 3.4.5 on Windows");

  script_tag(name:"solution", value:"Upgrade to PowerDNS Authoritative (Auth) Server
  3.3.3, or 3.4.5 or later.");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032220");
  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2015-01");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl", "os_detection.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!dnsPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!infos = get_app_version_and_proto(cpe:CPE, port:dnsPort)){
  exit(0);
}

version = infos["version"];
proto = infos["proto"];

if(version_in_range(version:version, test_version:"3.2.0", test_version2:"3.3.2"))
{
  fix = "3.3.3";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"3.4.0", test_version2:"3.4.4"))
{
  fix = "3.4.5";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:dnsPort, proto:proto);
  exit(0);
}
