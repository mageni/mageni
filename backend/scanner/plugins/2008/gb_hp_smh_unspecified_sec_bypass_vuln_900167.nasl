# Copyright (C) 2008 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900167");
  script_version("2021-10-14T13:27:28+0000");
  script_bugtraq_id(32088);
  script_cve_id("CVE-2008-4413");
  script_tag(name:"last_modification", value:"2021-10-15 09:20:32 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("HP/HPE System Management Homepage (SMH) Unspecified Security Bypass Vulnerability (HPSBMA02380)");
  script_dependencies("gb_hp_smh_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("hp/smh/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c01586921");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can leverage this issue to gain local unauthorized
  access.");

  script_tag(name:"affected", value:"HP/HPE SMH version 2.2.6 and prior on HP-UX B.11.11 and B.11.23

  HP SMH version 2.2.6 and 2.2.8 and prior on HP-UX B.11.23 and B.11.31");

  script_tag(name:"solution", value:"Update to version 2.2.9.1 or later.");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to a local security
  bypass vulnerability.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error, which can be
  exploited by local users to perform certain actions with escalated privileges.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("version_func.inc");

if (os_host_runs("hp-ux") != "yes")
  exit(0);

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"2.2.9.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.2.9.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);