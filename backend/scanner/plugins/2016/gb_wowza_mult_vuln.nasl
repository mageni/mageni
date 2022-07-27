###############################################################################
# OpenVAS Vulnerability Test
#
# Wowza Streaming Engine Multiple Vulnerabilities
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

CPE = 'cpe:/a:wowza:streaming_engine';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106225");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-07 11:27:17 +0700 (Wed, 07 Sep 2016)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Wowza Streaming Engine Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wowza_streaming_engine_detect.nasl");
  script_mandatory_keys("wowza_streaming_engine/installed", "wowza_streaming_engine/build");

  script_tag(name:"summary", value:"Wowza Streaming Engine is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The application interface allows users to perform certain actions via
HTTP requests without performing any validity checks to verify the requests. This can be exploited to perform
certain actions with administrative privileges if a logged-in user visits a malicious web site.

The application suffers from a privilege escalation issue. Normal user (read-only) can elevate his/her
privileges by sending a POST request setting the parameter 'accessLevel' to 'admin' gaining admin rights and/or
setting the parameter 'advUser' to 'true' and '_advUser' to 'on' gaining advanced admin rights.

Wowza Streaming Engine suffers from multiple reflected cross-site scripting vulnerabilities when input passed
via several parameters to several scripts is not properly sanitized before being returned to the user. This can
be exploited to execute arbitrary HTML and script code in a user's browser session in context of an affected
site.");

  script_tag(name:"impact", value:"Attackers may elevate their privileges or execute arbitrary scripts in the
users context.");

  script_tag(name:"affected", value:"All Wowza Streaming Engines until at least 4.5.0 build18676.");

  script_tag(name:"solution", value:"Update to version 4.6.0 build 19395.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40133/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40134/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40135/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (!build = get_kb_item("wowza_streaming_engine/build"))
  exit(0);

full_version = version + '.' + build;

if (version_is_less_equal(version: full_version, test_version: "4.5.0.18676")) {
  report = report_fixed_ver(installed_version: version + " build" + build, fixed_version: "4.6.0 build 19395");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
