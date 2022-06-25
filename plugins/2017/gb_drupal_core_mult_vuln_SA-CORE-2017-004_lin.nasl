###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_core_mult_vuln_SA-CORE-2017-004_lin.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# Drupal Core Multiple Vulnerabilities (SA-CORE-2017-004) (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811705");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2017-6923", "CVE-2017-6924", "CVE-2017-6925");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-08-17 10:13:39 +0530 (Thu, 17 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Drupal Core Multiple Vulnerabilities (SA-CORE-2017-004) (Linux)");

  script_tag(name:"summary", value:"This host is running Drupal and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in the 'views' subsystem/module which did not restrict access to
    the Ajax endpoint to only views configured to use Ajax.

  - An error when using the REST API, users without the correct permission can
    post comments via REST that are approved even if the user does not have
    permission to post approved comments.

  - An error in the entity access system that could allow unwanted access to
    view, create, update, or delete entities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions.");

  script_tag(name:"affected", value:"Drupal core version 8.x versions prior to
  8.3.7 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Drupal core version 8.3.7 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2017-004");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.drupal.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!drupalPort= get_app_port(cpe:CPE)){
  exit(0);
}

if(!drupalVer = get_app_version(cpe:CPE, port:drupalPort, version_regex:"^[0-9]\.[0-9.]+")){
  exit(0);
}

if(drupalVer =~ "^(8\.)" && version_is_less(version:drupalVer, test_version:"8.3.7"))
{
  report = report_fixed_ver(installed_version:drupalVer, fixed_version:"8.3.7");
  security_message(data:report, port:drupalPort);
  exit(0);
}
