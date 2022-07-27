##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_isc_bind_edns_option_processing_dos_vuln_lin.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# ISC BIND EDNS Option Processing Denial of Service Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810519");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2014-3859");
  script_bugtraq_id(68193);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-24 14:33:17 +0530 (Tue, 24 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND EDNS Option Processing Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"The host is installed with ISC BIND and is
  prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  EDNS option processing by libdns.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit) via
  crafted data.");

  script_tag(name:"affected", value:"ISC BIND versions 9.10.0, 9.10.0-P1
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to ISC BIND version 9.10.0-P2 or
  later on Linux.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01171");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030414");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34607");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("bind_version.nasl", "os_detection.nasl");
  script_mandatory_keys("ISC BIND/installed", "Host/runs_unixoide");
  script_xref(name:"URL", value:"https://www.isc.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("revisions-lib.inc");

if(!bindPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_proto(cpe:CPE, port:bindPort)){
  exit(0);
}

bindVer = infos["version"];
proto = infos["proto"];

if(bindVer =~ "^(9\.10)")
{
  if(version_is_less(version:bindVer, test_version:"9.10.0.P2"))
  {
    report = report_fixed_ver(installed_version:bindVer, fixed_version:"9.10.0-P2");
    security_message(data:report, port:bindPort, proto:proto);
    exit(0);
  }
}

exit(99);