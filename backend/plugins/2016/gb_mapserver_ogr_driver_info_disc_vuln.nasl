###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mapserver_ogr_driver_info_disc_vuln.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# MapServer OGR Driver Information Disclosure Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:umn:mapserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810316");
  script_version("$Revision: 12431 $");
  script_cve_id("CVE-2016-9839");
  script_bugtraq_id(94856);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-21 18:17:45 +0530 (Wed, 21 Dec 2016)");
  script_name("MapServer OGR Driver Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is running MapServer
  and is prone to Information Disclosure Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to OGR driver does not handle
  data connection properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain sensitive information via error messages.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"MapServer versions before 7.0.3.");

  script_tag(name:"solution", value:"Upgrade to version 7.0.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://github.com/mapserver/mapserver/pull/5356");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_mapserver_detect.nasl");
  script_mandatory_keys("MapServer/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.mapserver.org");
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

if(version_is_less(version:webVer, test_version:"7.0.3"))
{
  report = report_fixed_ver( installed_version:webVer, fixed_version:"7.0.3");
  security_message( data:report, port:webPort);
  exit(0);
}
exit(0);
