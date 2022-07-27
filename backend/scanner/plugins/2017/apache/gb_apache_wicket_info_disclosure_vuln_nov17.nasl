##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_wicket_info_disclosure_vuln_nov17.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache Wicket Information Disclosure Vulnerability Nov17
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

CPE = "cpe:/a:apache:wicket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812103");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2014-3526");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-10 16:11:14 +0530 (Fri, 10 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Wicket Information Disclosure Vulnerability Nov17");

  script_tag(name:"summary", value:"This host is running Apache Wicket and is
  prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as when storing the page
  markup at the server side Wicket uses as an identifier a pair of the current
  session id plus the new url. However, Wicket does not check if user session
  is temporary.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Apache Wicket before 1.5.12, 6.x before 6.17.0,
  and 7.x before 7.0.0-M3");

  script_tag(name:"solution", value:"Upgrade to Apache Wicket versions 1.5.12
  6.17.0, 7.0.0-M3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://wicket.apache.org/news/2014/09/22/cve-2014-3526.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_detect.nasl");
  script_mandatory_keys("Apache/Wicket/Installed");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"http://wicket.apache.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wkPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:wkPort, exit_no_version:TRUE)) exit(0);
wkVer = infos['version'];
wkpath = infos['location'];

if(version_is_less(version:wkVer, test_version:"1.5.12")){
  fix = "1.5.12";
}

else if(version_in_range(version:wkVer, test_version:"7.0", test_version2:"7.0.0.M2")){
  fix = "7.0.0-M3";
}

else if(wkVer =~ "^(6\.)")
{
  if(version_is_less(version:wkVer, test_version:"6.17.0")){
    fix = "6.17.0";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:wkVer, fixed_version:fix, install_path:wkpath);
  security_message(data:report, port:wkPort);
  exit(0);
}
exit(0);
