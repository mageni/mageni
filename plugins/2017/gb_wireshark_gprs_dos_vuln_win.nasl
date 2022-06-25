###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_gprs_dos_vuln_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Wireshark 'GPRS' DoS Vulnerability (Windows)
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811428");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-11409");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-20 18:12:24 +0530 (Thu, 20 Jul 2017)");
  script_name("Wireshark 'GPRS' DoS Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  GPRS LLC dissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to crash the affected application, resulting in denial-of-service
  conditions.");

  script_tag(name:"affected", value:"Wireshark version 2.0.0 to 2.0.13 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.0.14 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-37.html");
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

if(wirversion =~ "(^2\.0)")
{
  if(version_is_less(version:wirversion, test_version:"2.0.14"))
  {
    report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.0.14");
    security_message(data:report);
    exit(0);
  }
}
