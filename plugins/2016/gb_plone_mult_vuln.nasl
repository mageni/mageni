###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plone_mult_vuln.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Plone CMS Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:plone:plone";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106358");
  script_version("$Revision: 12431 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-31 13:26:41 +0700 (Mon, 31 Oct 2016)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2016-7135", "CVE-2016-7136", "CVE-2016-7137", "CVE-2016-7138", "CVE-2016-7139",
                "CVE-2016-7140", "CVE-2016-7147", "CVE-2017-5524");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plone CMS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_plone_detect.nasl");
  script_mandatory_keys("plone/installed");

  script_tag(name:"summary", value:"Plone CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Plone CMS is prone to multiple vulnerabilities:

  - A bypass of the sandbox protection mechanism. (CVE-2017-5524)

  - Several Reflected Cross-Site Scripting were found within the application. (CVE-2016-7136, CVE-2016-7138,
CVE-2016-7139, CVE-2016-7140)

  - A Path traversal vulnerability was found within the application that allows to browse filesystem files using
the permissions of the user who is running the service. (CVE-2016-7135)

  - 3 Instances of an open redirection were found within the application, allowing any user to be redirected to
an external website and therefore steal the user's credentials. (CVE-2016-7137)");

  script_tag(name:"impact", value:"An attacker may access arbitrary system files, inject arbitrary web scripts
or redirect users to arbitrary web sites.");

  script_tag(name:"affected", value:"Plone CMS version 3.x, 4.x and 5.x");

  script_tag(name:"solution", value:"Apply the hotfix or update to Plone 4.3.12, 5.0.7 or later.");

  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20160830");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20170117");
  script_xref(name:"URL", value:"https://plone.org/security/hotfix/20170117/sandbox-escape");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.12");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
