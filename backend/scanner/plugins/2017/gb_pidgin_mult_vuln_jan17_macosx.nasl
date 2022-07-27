###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_mult_vuln_jan17_macosx.nasl 66254 2017-01-18 07:41:15Z$
#
# Pidgin Multiple Vulnerabilities Jan 2017 (MAC OS X)
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

CPE = "cpe:/a:pidgin:pidgin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809871");
  script_version("$Revision: 12408 $");
  script_cve_id("CVE-2016-2365", "CVE-2016-2366", "CVE-2016-2367", "CVE-2016-2368",
 		"CVE-2016-2369", "CVE-2016-2370", "CVE-2016-2371", "CVE-2016-2372",
		"CVE-2016-2373", "CVE-2016-2374", "CVE-2016-2375", "CVE-2016-2376",
		"CVE-2016-2377", "CVE-2016-2378", "CVE-2016-2380", "CVE-2016-4323",
                "CVE-2016-1000030");
  script_bugtraq_id(91335);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 10:34:54 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-01-18 13:03:03 +0530 (Wed, 18 Jan 2017)");
  script_name("Pidgin Multiple Vulnerabilities Jan 2017 (MAC OS X)");

  script_tag(name:"summary", value:"This host is installed with Pidgin and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exists due to,

  - The X.509 certificates may be improperly imported when using GnuTLS.

  - An improper validation in the field and attribute counts.

  - An improper validation of the incoming message format.

  - An improper validation of the received values.

  - An error in chunk decoding.

  - Not checking the field count before accessing the fields.

  - The multiple issues in the MXit protocol support.

  - An error in g_vsnprintf().

  - An improper validation of the data length in the MXit protocol support.

  - An improper usage of data types in the MXit protocol support.

  - Not checking the length of the font tag.
  Refer the reference link for more information.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow attackers to cause denial of service, execute
  arbitrary code and disclose information from memory.");

  script_tag(name:"affected", value:"Pidgin before version 2.11.0 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.11.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.pidgin.im/news/security");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0133");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_pidgin_detect_macosx.nasl");
  script_mandatory_keys("Pidgin/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.pidgin.im");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!pidVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:pidVer, test_version:"2.11.0"))
{
  report = report_fixed_ver(installed_version:pidVer, fixed_version:"2.11.0");
  security_message(data:report);
  exit(0);
}
