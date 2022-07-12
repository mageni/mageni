###############################################################################
# OpenVAS Vulnerability Test
#
# Apple iTunes Multiple Vulnerabilities - Mar12 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802824");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2011-2825", "CVE-2011-2833", "CVE-2011-2846", "CVE-2011-2847",
                "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2857", "CVE-2011-2860",
                "CVE-2011-2866", "CVE-2011-2867", "CVE-2011-2868", "CVE-2011-2869",
                "CVE-2011-2870", "CVE-2011-2871", "CVE-2011-2872", "CVE-2011-2873",
                "CVE-2011-2877", "CVE-2011-3885", "CVE-2011-3888", "CVE-2011-3897",
                "CVE-2011-3908", "CVE-2011-3909", "CVE-2012-0591", "CVE-2012-0592",
                "CVE-2012-0593", "CVE-2012-0594", "CVE-2012-0595", "CVE-2012-0596",
                "CVE-2012-0597", "CVE-2012-0598", "CVE-2012-0599", "CVE-2012-0600",
                "CVE-2012-0601", "CVE-2012-0602", "CVE-2012-0603", "CVE-2012-0604",
                "CVE-2012-0605", "CVE-2012-0606", "CVE-2012-0607", "CVE-2012-0608",
                "CVE-2012-0609", "CVE-2012-0610", "CVE-2012-0611", "CVE-2012-0612",
                "CVE-2012-0613", "CVE-2012-0614", "CVE-2012-0615", "CVE-2012-0616",
                "CVE-2012-0617", "CVE-2012-0618", "CVE-2012-0619", "CVE-2012-0620",
                "CVE-2012-0621", "CVE-2012-0622", "CVE-2012-0623", "CVE-2012-0624",
                "CVE-2012-0625", "CVE-2012-0626", "CVE-2012-0627", "CVE-2012-0628",
                "CVE-2012-0629", "CVE-2012-0630", "CVE-2012-0631", "CVE-2012-0632",
                "CVE-2012-0633", "CVE-2012-0634", "CVE-2012-0635", "CVE-2012-0636",
                "CVE-2012-0637", "CVE-2012-0638", "CVE-2012-0639", "CVE-2012-0648");
  script_bugtraq_id(49279, 52365, 49658, 52363, 49938, 50360, 50642, 51041);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2012-03-20 16:59:10 +0530 (Tue, 20 Mar 2012)");
  script_name("Apple iTunes Multiple Vulnerabilities - Mar12 (Windows)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5191");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521910");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Mar/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code or inject html code via unknown vectors.");
  script_tag(name:"affected", value:"Apple iTunes version prior to 10.6 (10.6.0.40) on Windows");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer to the links given below.");
  script_tag(name:"solution", value:"Upgrade to Apple Apple iTunes version 10.6 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple iTunes and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.apple.com/itunes/download/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

## Apple iTunes version < 10.6 (10.6.0.40)
if( version_is_less( version:vers, test_version:"10.6.0.40" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.6.0.40", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );