###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantisbt_mult_vuln_june16_lin.nasl 12818 2018-12-18 09:55:03Z ckuersteiner $
#
# MantisBT SOAP API Information Disclosure Vulnerability - June16 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:mantisbt:mantisbt";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808209");
  script_version("$Revision: 12818 $");
  script_cve_id("CVE-2014-9759");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 17:28:33 +0530 (Fri, 03 Jun 2016)");

  script_name("MantisBT SOAP API Information Disclosure Vulnerability - June16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with MantisBT
  and is prone to an incomplete blacklist vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incomplete blacklist
  vulnerability in the config_is_private function in 'config_api.php script' .
  When a new config is added or an existing one is renamed, the black list must
  be updated accordingly. If this is not or incorrectly done, the
  config becomes available via SOAP API");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain sensitive master salt configuration information via a SOAP API request.");

  script_tag(name:"affected", value:"MantisBT versions 1.3.x before 1.3.0
  on Linux");

  script_tag(name:"solution", value:"Upgrade to MantisBT version 1.3.0-rc.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/01/02/1");
  script_xref(name:"URL", value:"https://mantisbt.org/bugs/view.php?id=20277");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mantis_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mantisbt/detected", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!manPort = get_app_port(cpe:CPE))
  exit(0);

if(!manVer = get_app_version(cpe:CPE, port:manPort))
  exit(0);

## >= 1.3.0-beta.1
##Fixed in versions:1.3.0 (not yet released), possibly 1.3.0-rc.2
if(version_is_equal(version:manVer, test_version:"1.3.0-beta.1") ||
   version_is_equal(version:manVer, test_version:"1.3.0-beta.2") ||
   version_is_equal(version:manVer, test_version:"1.3.0-beta.3") ||
   version_is_equal(version:manVer, test_version:"1.3.0-rc.1"))
{
  report = report_fixed_ver(installed_version:manVer, fixed_version:"1.3.0-rc.2");
  security_message(data:report, port:manPort);
  exit(0);
}

exit(99);
