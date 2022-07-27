##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bitdefender_ts_bdfwfpf_driver_local_priv_escalation_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Bitdefender Total Security 'bdfwfpf' Kernel Driver Privilege Escalation Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:bitdefender:total_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811803");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-10950");
  script_bugtraq_id(100418);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-05 16:45:12 +0530 (Tue, 05 Sep 2017)");
  script_name("Bitdefender Total Security 'bdfwfpf' Kernel Driver Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Bitdefender
  Total Security and is prone to local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error with the
  processing of the 0x8000E038 IOCTL in the bdfwfpf driver. The issue results
  from the lack of validating the existence of an object prior to performing
  operations on the object.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code in the context of SYSTEM with elevated
  privileges.");

  script_tag(name:"affected", value:"Bitdefender Total Security 21.0.24.62.");

  script_tag(name:"solution", value:"Update to version 21.2.25.30 (AV 2017), 22.0.8.114 (AV 2018) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://vuldb.com/de/?id.105907");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-17-693/");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_bitdefender_prdts_detect.nasl");
  script_mandatory_keys("BitDefender/TotalSec/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!bitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(bitVer == "21.0.24.62")
{
  report = report_fixed_ver(installed_version:bitVer, fixed_version:"21.2.25.30");
  security_message(data:report);
  exit(0);
}

exit(0);
