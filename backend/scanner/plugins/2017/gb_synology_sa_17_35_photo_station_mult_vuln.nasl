###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synology_sa_17_35_photo_station_mult_vuln.nasl 12467 2018-11-21 14:04:59Z cfischer $
#
# Synology Photo Station Multiple Vulnerabilities (SA_17_35)
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

CPE = "cpe:/a:synology:synology_photo_station";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812224");
  script_version("$Revision: 12467 $");
  script_cve_id("CVE-2017-11161", "CVE-2017-11162", "CVE-2017-12071");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 15:04:59 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-23 13:23:39 +0530 (Thu, 23 Nov 2017)");
  script_name("Synology Photo Station Multiple Vulnerabilities (SA_17_35)");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_synology_photo_station_detect.nasl");
  script_mandatory_keys("synology_photo_station/installed", "synology_photo_station/psv");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/support/security/Synology_SA_17_35_PhotoStation");

  script_tag(name:"summary", value:"The host is installed with Synology
  Photo Station and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  input validation errors in 'url' parameter while downloading and reading
  arbitrary files, insufficient input validation in article_id parameter to
  'label.php' script and insufficient input validation in type parameter to
  'synotheme.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  remote attacker to execute arbitrary SQL commands, read arbitrary files
  and download arbitrary local files.");

  script_tag(name:"affected", value:"Synology Photo Station before 6.7.4-3433
  and 6.3-2968.");

  script_tag(name:"solution", value:"Upgrade to Photo Station to 6.7.4-3433
  or (6.3-2968 for DSM 5.2 users).");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!synport = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location( cpe:CPE, port:synport, exit_no_version:TRUE)) exit(0);
synVer = infos['version'];
synpath = infos['location'];

if(version_is_less(version:synVer, test_version: "6.3-2968")){
  fix = "6.3-2968";
}

else if(version_in_range(version:synVer, test_version:"6.7", test_version2:"6.7.3-3432") ||
   version_in_range(version:synVer, test_version:"6.6", test_version2:"6.6.3-3347") ||
   version_in_range(version:synVer, test_version:"6.5", test_version2:"6.5.3-3226") ||
   version_in_range(version:synVer, test_version:"6.4", test_version2:"6.4-3166")){
  fix = "6.7.3-3433";
}

if(fix){
  report = report_fixed_ver(installed_version:synVer, fixed_version:fix, install_path:synpath);
  security_message(port:synport, data: report);
}

exit(0);