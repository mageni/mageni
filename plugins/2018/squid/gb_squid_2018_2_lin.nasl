###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_2018_2_lin.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Squid Proxy Cache Security Update Advisory SQUID-2018:2 (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = 'cpe:/a:squid-cache:squid';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107296");
  script_cve_id("CVE-2018-1000027");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-09 19:08:28 +0100 (Fri, 09 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Proxy Cache Security Update Advisory SQUID-2018:2 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_squid_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid_proxy_server/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Squid is vulnerable to denial of service attack
  when processing ESI responses.

  This NVT has been deprecated and merged into 'Squid Proxy Cache Security Update Advisory SQUID-2018:2'
  (OID:1.3.6.1.4.1.25623.1.0.107297)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to incorrect pointer handling Squid is vulnerable
  to denial of service attack when processing ESI responses or downloading intermediate CA
  certificates.");

  script_tag(name:"impact", value:"This problem allows a remote server delivering certain
  ESI response syntax to trigger a denial of service for all clients accessing the Squid service.");

  script_tag(name:"affected", value:"Squid 3.x -> 3.5.27, Squid 4.x -> 4.0.22.");

  script_tag(name:"solution", value:"Updated Packages:

  This bug is fixed by Squid version 4.0.23.

  In addition, patches addressing this problem for the stable
  releases can be found in our patch archives for Squid 3.5 and Squid 4.

  If you are using a prepackaged version of Squid then please refer
  to the package vendor for availability information on updated
  packages.");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2018_2.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v3/3.5/changesets/SQUID-2018_2.patch");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Versions/v4/changesets/SQUID-2018_2.patch");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^3\.") {
  if (version_is_less_equal(version: version, test_version: "3.5.27")) {
    report = report_fixed_ver(installed_version: version, fixed_version:"" );
  }
} else if (version =~ "^4\.") {
  if (version_is_less_equal(version: version, test_version: "4.0.22")) {
    report = report_fixed_ver(installed_version: version, fixed_version:"" );
  }
}

if (! isnull (report))
{
    security_message(port: port, data: report);
    exit(0);
}

exit(99);
