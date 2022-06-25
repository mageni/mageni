###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_network_cameras_mult_vuln_apr17.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Axis Network Cameras Multiple Vulnerabilities Apr17
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:axis:network_camera";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810932");
  script_version("$Revision: 11863 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-20 13:14:28 +0530 (Thu, 20 Apr 2017)");
  script_name("Axis Network Cameras Multiple Vulnerabilities Apr17");

  script_tag(name:"summary", value:"The host is running Axis Network Cameras and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Axis software does not have any cross-site request forgery protection
    within the management interface.

  - No server-side security checks are present for Axis software.

  - Few Web service runs as root.

  - Lack of CSRF protection while using script editor function
    '/admin-bin/editcgi.cgi'.

  - Multiple root setuid .CGI scripts and binaries are present.

  - No option existed in Axis software to disable the HTTP interface. The web
    server will always listen on all network interfaces of the camera.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain root access to the device, execute arbitrary code and
  cause denial of service condition.");

  script_tag(name:"affected", value:"Axis Camera

  Model P1204, software versions <= 5.50.4

  Model P3225, software versions <= 6.30.1

  Model P3367, software versions <= 6.10.1.2

  Model M3045, software versions <= 6.15.4.1

  Model M3005, software versions <= 5.50.5.7

  Model M3007, software versions <= 6.30.1.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Mar/41");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_axis_network_cameras_ftp_detect.nasl");
  script_mandatory_keys("axis/camera/version", "axis/camera/model");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!axport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!(version = get_app_version(cpe:CPE, port:axport)) ||
   !(model = get_kb_item("axis/camera/model"))){
  exit(0);
}

if(model == "P1204" && version_is_less_equal(version:version, test_version:"5.50.4") ||
   model == "P3225" && version_is_less_equal(version:version, test_version:"6.30.1") ||
   model == "P3367" && version_is_less_equal(version:version, test_version:"6.10.1.2") ||
   model == "M3045" && version_is_less_equal(version:version, test_version:"6.15.4.1") ||
   model == "M3005" && version_is_less_equal(version:version, test_version:"5.50.5.7") ||
   model == "M3007" && version_is_less_equal(version:version, test_version:"6.30.1.1")){
  report = report_fixed_ver(installed_version:model + " " + version, fixed_version:"None Available");
  security_message(port:axport, data:report);
  exit(0);
}

exit(99);
