###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortianalyzer_FG-IR-17-014.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# FortiAnalyzer Open Redirect Vulnerability
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

CPE = "cpe:/h:fortinet:fortianalyzer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140264");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-01 16:24:31 +0700 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2017-3126");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FortiAnalyzer Open Redirect Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortianalyzer_version.nasl");
  script_mandatory_keys("fortianalyzer/version");

  script_tag(name:"summary", value:"The FortiAnalyzer WebUI accept a user-controlled input that specifies a link
to an external site, and uses that link in a redirect.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Open redirect");

  script_tag(name:"affected", value:"FortiAnalyzer versions 5.4.0 to 5.4.2.");

  script_tag(name:"solution", value:"Upgrade to version 5.4.3 or later.");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-17-014");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
