###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_profinet_io_dissector_dos_vuln_win.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Wireshark 'Profinet I/O' Dissector DoS Vulnerability (Windows)
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811801");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2017-13766");
  script_bugtraq_id(100542);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-05 15:05:11 +0530 (Tue, 05 Sep 2017)");
  script_name("Wireshark 'Profinet I/O' Dissector DoS Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds
  write error in 'plugins/profinet/packet-dcerpc-pn-io.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to make Wireshark crash by injecting a malformed packet onto
  the wire or by convincing someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0, 2.2.0 to 2.2.8
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.1 or
  2.2.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-39.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(wirversion == "2.4.0"){
  fix = "2.4.1";
}

else if(wirversion =~ "(^2\.2)")
{
  if(version_is_less(version:wirversion, test_version:"2.2.9")){
    fix = "2.2.9";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
