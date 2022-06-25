###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_avp_local_ca_root_sec_bypass_vuln.nasl 11501 2018-09-20 12:19:13Z mmartin $
#
# Kaspersky Local CA Root Security Bypass Vulnerability
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

CPE = "cpe:/a:kaspersky_lab:kaspersky_internet_security_2017";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810264");
  script_version("$Revision: 11501 $");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 14:19:13 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-06 13:28:45 +0530 (Fri, 06 Jan 2017)");
  script_name("Kaspersky Local CA Root Security Bypass Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Kaspersky Antivirus
  products is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the private key generated
  by Kaspersky for the local root is incorrectly protected.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote
  attackers to escalate privileges.");

  script_tag(name:"affected", value:"Kaspersky AVP version 17.0.0");

  script_tag(name:"solution", value:"Kaspersky has fixed this issue in the autoupdated patches that were issued by December 28. To apply the fixes, please update your products.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40988");
  script_xref(name:"URL", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=989");
  script_xref(name:"URL", value:"https://support.kaspersky.com/vulnerability.aspx?el=12430#281216");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/products/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!kasVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:kaspersky:kaspersky_anti-virus_2017";
  if(!kasVer = get_app_version(cpe:CPE))
  {
    CPE = "cpe:/a:kaspersky:kaspersky_total_security_2017";
    if(!kasVer = get_app_version(cpe:CPE)){
      exit(0);
    }
  }
}

if(!kasVer){
  exit(0);
}

## Installed 2017 version. Currently the version is 17.0.0.611
if(version_is_equal(version:kasVer, test_version:"17.0.0.611"))
{
  report = report_fixed_ver(installed_version:kasVer, fixed_version:"See Vendor.");
  security_message(data:report);
  exit(0);
}
