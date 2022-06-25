###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mapserver_wfs_feature_bof_vuln_lin.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# MapServer WFS Feature Requests Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:umn:mapserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810791");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-5522");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-06 12:11:11 +0530 (Tue, 06 Jun 2017)");
  script_name("MapServer WFS Feature Requests Buffer Overflow Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running MapServer and is prone
  to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'WFS' get
  feature requests. Does not handle with specific WFS get feature requests
  properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to crash the service, or potentially execute arbitrary code.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"affected", value:"MapServer versions before 6.0.6,
  6.2.x before 6.2.4, 6.4.x before 6.4.5, and 7.0.x before 7.0.4 on Linux.");

  script_tag(name:"solution", value:"Upgrade to version 6.0.6, 6.2.4, 6.4.5,
  7.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://lists.osgeo.org/pipermail/mapserver-dev/2017-January/015007.html");
  script_xref(name:"URL", value:"http://www.mapserver.org/development/changelog/changelog-6-4.html#changelog-6-4-5");
  script_xref(name:"URL", value:"http://www.mapserver.org/development/changelog/changelog-7-0.html#changelog-7-0-4");
  script_xref(name:"URL", value:"https://github.com/mapserver/mapserver/commit/e52a436c0e1c5e9f7ef13428dba83194a800f4df");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("os_detection.nasl", "gb_mapserver_detect.nasl");
  script_mandatory_keys("MapServer/Installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!webPort = get_app_port(cpe:CPE)){
 exit(0);
}

if(!webVer = get_app_version(cpe:CPE, port:webPort)){
 exit(0);
}

if(version_is_less(version:webVer, test_version:"6.0.6")){
  fix = "6.0.6";
}
else if((webVer =~ "^6\.2\.") && version_is_less(version:webVer, test_version:"6.2.4")){
  fix = "6.2.4";
}
else if((webVer =~ "^6\.4\.") && version_is_less(version:webVer, test_version:"6.4.5")){
  fix = "6.4.5";
}
else if((webVer =~ "^7\.0\.") && version_is_less(version:webVer, test_version:"7.0.4")){
  fix = "7.0.4";
}

if(fix)
{
  report = report_fixed_ver( installed_version:webVer, fixed_version:fix);
  security_message( data:report, port:webPort);
  exit(0);
}
