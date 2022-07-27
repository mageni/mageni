###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_qcp_dos_vuln_win.nasl 11596 2018-09-25 09:49:46Z asteins $
#
# RealNetworks RealPlayer 'QCP' Denial of Service Vulnerability (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:realnetworks:realplayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809399");
  script_version("$Revision: 11596 $");
  script_cve_id("CVE-2016-9018");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 11:49:46 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-11-03 11:05:43 +0530 (Thu, 03 Nov 2016)");
  script_name("RealNetworks RealPlayer 'QCP' Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with RealPlayer
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper handling
  of a repeating VRAT chunk in qcpfformat.dll.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a Null pointer dereference and to crash the application.");

  script_tag(name:"affected", value:"RealNetworks RealPlayer version 18.1.5.705
  on Windows.");

  script_tag(name:"solution", value:"Update RealPlayer to version 18.1.6.161");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40617");
  script_xref(name:"URL", value:"https://customer.real.com/hc/en-gb/articles/214793317-RealNetworks-product-security-updates");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!realVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:realVer, test_version:"18.1.5.705"))
{
  report = report_fixed_ver(installed_version:realVer, fixed_version:"18.1.6.161");
  security_message(data:report);
  exit(0);
}
