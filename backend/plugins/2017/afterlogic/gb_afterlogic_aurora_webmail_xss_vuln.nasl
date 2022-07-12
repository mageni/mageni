###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_afterlogic_aurora_webmail_xss_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# AfterLogic Aurora/Webmail XSS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:afterlogic:aurora';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140384");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-21 12:49:43 +0700 (Thu, 21 Sep 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2017-14597");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("AfterLogic Aurora/Webmail XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_afterlogic_aurora_webmail_detect.nasl");
  script_mandatory_keys("afterlogic_aurora_webmail/installed");

  script_tag(name:"summary", value:"AfterLogic Aurora and WebMail are prone to a cross-site scripting
vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"AdminPanel in AfterLogic WebMail and Aurora has an XSS via the
txtDomainName field to adminpanel/modules/pro/inc/ajax.php during addition of a domain.");

  script_tag(name:"solution", value:"There is currently no fixed version available. AfterLogic provides
however a temporary fix.");

  script_xref(name:"URL", value:"https://auroramail.wordpress.com/2017/08/28/vulnerability-in-webmailaurora-closed/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "7.7", test_version2: "7.7.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Workaround");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
