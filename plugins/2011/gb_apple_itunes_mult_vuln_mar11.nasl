###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Multiple Vulnerabilities - Mar11
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801907");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0111", "CVE-2011-0112", "CVE-2011-0113", "CVE-2011-0114",
                "CVE-2011-0115", "CVE-2011-0116", "CVE-2011-0117", "CVE-2011-0118",
                "CVE-2011-0119", "CVE-2011-0120", "CVE-2011-0121", "CVE-2011-0122",
                "CVE-2011-0123", "CVE-2011-0124", "CVE-2011-0125", "CVE-2011-0126",
                "CVE-2011-0127", "CVE-2011-0128", "CVE-2011-0129", "CVE-2011-0130",
                "CVE-2011-0131", "CVE-2011-0132", "CVE-2011-0133", "CVE-2011-0134",
                "CVE-2011-0135", "CVE-2011-0136", "CVE-2011-0137", "CVE-2011-0138",
                "CVE-2011-0139", "CVE-2011-0140", "CVE-2011-0141", "CVE-2011-0142",
                "CVE-2011-0143", "CVE-2011-0144", "CVE-2011-0145", "CVE-2011-0146",
                "CVE-2011-0147", "CVE-2011-0148", "CVE-2011-0149", "CVE-2011-0150",
                "CVE-2011-0151", "CVE-2011-0152", "CVE-2011-0153", "CVE-2011-0154",
                "CVE-2011-0155", "CVE-2011-0156", "CVE-2011-0165", "CVE-2011-0164",
                "CVE-2011-0168", "CVE-2011-0170", "CVE-2011-0191", "CVE-2011-0192");
  script_bugtraq_id(46654);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple iTunes Multiple Vulnerabilities - Mar11");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4554");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0559");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00000.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attacker to cause denial of service or
  obtain system privileges during installation.");
  script_tag(name:"affected", value:"Apple iTunes version prior to 10.2 (10.2.0.34)");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer to the liks given below.");
  script_tag(name:"solution", value:"Upgrade to Apple Apple iTunes version 10.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host has iTunes installed, which is prone to multiple
  vulnerabilities.");
  script_xref(name:"URL", value:"http://www.apple.com/itunes/download/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

#  Apple iTunes version < 10.2 (10.2.0.34)
if( version_is_less( version:vers, test_version:"10.2.0.34")){
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.2.0.34", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
